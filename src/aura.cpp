/*

   Copyright [2010] [Josko Nikolic]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   CODE PORTED FROM THE ORIGINAL GHOST PROJECT: http://ghost.pwner.org/

 */

#include "aura.h"
#include "crc32.h"
#include "sha1.h"
#include "csvparser.h"
#include "config.h"
#include "socket.h"
#include "auradb.h"
#include "bnet.h"
#include "map.h"
#include "gameplayer.h"
#include "gameprotocol.h"
#include "gpsprotocol.h"
#include "game.h"
#include "irc.h"
#include "TCPBroadcast.h"
#include "util.h"
#include "fileutil.h"

#include <csignal>
#include <cstdlib>
#include <thread>
#include <fstream>

#define __STORMLIB_SELF__
#include <StormLib.h>

#ifdef WIN32
#define NOMINMAX
#include <ws2tcpip.h>
#include <winsock.h>
#include <process.h>
#endif

#define VERSION "3.0"

using namespace std;

#undef FD_SETSIZE
#define FD_SETSIZE 512

static CAura* gAura    = nullptr;
bool          gRestart = false;

void Print2(const string& message)
{
  Print(message);

  if (gAura->m_IRC)
    gAura->m_IRC->SendMessageIRC(message, string());
}

void Print3(const string& message,const string& owner)
{
  if (gAura->m_IRC)
    gAura->m_IRC->SendMessageIRC(message, owner);
}

//
// main
//

int main(const int, const char* argv[])
{
  // seed the PRNG

  srand(static_cast<uint32_t>(time(nullptr)));

  // disable sync since we don't use cstdio anyway

  ios_base::sync_with_stdio(false);

  // read config file

  CConfig CFG;
  CFG.Read("aura.cfg");

  Print("[MobaZ] starting up");

  signal(SIGINT, [](int32_t) -> void {
    Print("[!!!] caught signal SIGINT, exiting NOW");

    if (gAura)
    {
      if (gAura->m_Exiting)
        exit(1);
      else
        gAura->m_Exiting = true;
    }
    else
      exit(1);
  });

#ifndef WIN32
  // disable SIGPIPE since some systems like OS X don't define MSG_NOSIGNAL

  signal(SIGPIPE, SIG_IGN);
#endif

  // print timer resolution

  Print("[MobaZ] using monotonic timer with resolution " + std::to_string(static_cast<double>(std::chrono::steady_clock::period::num) / std::chrono::steady_clock::period::den * 1e9) + " nanoseconds");

#ifdef WIN32
  // initialize winsock

  Print("[MobaZ] starting winsock");
  WSADATA wsadata;

  if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
  {
    Print("[MobaZ] error starting winsock");
    return 1;
  }

  // increase process priority

  Print("[MobaZ] setting process priority to \"high\"");
  SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#endif

  // initialize aura

  gAura = new CAura(&CFG);

  // check if it's properly configured

  if (gAura->GetReady())
  {
    // loop

    while (!gAura->Update())
      ;
  }
  else
    Print("[MobaZ] check your aura.cfg and configure Aura properly");

  // shutdown aura

  Print("[MobaZ] shutting down");
  delete gAura;

#ifdef WIN32
  // shutdown winsock

  Print("[MobaZ] shutting down winsock");
  WSACleanup();
#endif

  // restart the program

  if (gRestart)
  {
#ifdef WIN32
    _spawnl(_P_OVERLAY, argv[0], argv[0], nullptr);
#else
    execl(argv[0], argv[0], nullptr);
#endif
  }

  return 0;
}

//
// CAura
//

int CAura::GetPortFree()
{
  int                sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in serv_addr;
  socklen_t          len    = sizeof(serv_addr);
  serv_addr.sin_family      = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port        = 0;

  if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
  {
    cout << "failed to bind with errno: " << errno << endl;
    exit(1);
  }
  if (getsockname(sockfd, (struct sockaddr*)&serv_addr, &len) < 0)
  {
    cout << "failed to get hostname with errno: " << errno << endl;
    exit(1);
  }
  return serv_addr.sin_port;
}

CAura::CAura(CConfig* CFG)
  : m_IRC(nullptr),
    m_UDPSocket(new CUDPSocket()),
    m_ReconnectSocket(new CTCPServer()),
    m_GPSProtocol(new CGPSProtocol()),
    m_CRC(new CCRC32()),
    m_SHA(new CSHA1()),
    m_CurrentGame(nullptr),
    m_DB(new CAuraDB(CFG)),
    m_Map(nullptr),
    m_Version(VERSION),
    m_HostCounter(1),
    m_Exiting(false),
    m_Enabled(true),
    m_Ready(true),
    m_Broadcast(nullptr)
{
  Print("[MobaZ] MobaZ Host v " + m_Version + " - with GProxy++ support");

  // get the general configuration variables

  m_UDPSocket->SetBroadcastTarget(CFG->GetString("udp_broadcasttarget", string()));
  m_UDPSocket->SetDontRoute(CFG->GetInt("udp_dontroute", 0) == 0 ? false : true);

  m_ReconnectPort = CFG->GetInt("bot_reconnectport", gAura->GetPortFree());

  if (m_ReconnectSocket->Listen(m_BindAddress, m_ReconnectPort))
    Print("[MobaZ] listening for GProxy++ reconnects on port " + to_string(m_ReconnectPort));
  else
  {
    Print("[MobaZ] error listening for GProxy++ reconnects on port " + to_string(m_ReconnectPort));
    m_Ready = false;
    return;
  }

  m_CRC->Initialize();
  m_HostPort       = CFG->GetInt("bot_hostport", gAura->GetPortFree());
  m_DefaultMap     = CFG->GetString("bot_defaultmap", "dota10");
  m_LANWar3Version = CFG->GetInt("lan_war3version", 26);
  m_NumPlayersToStartGameOver = CFG->GetInt("bot_gameoverplayernumber", 1);

  // read the rest of the general configuration

  SetConfigs(CFG);

  // get the irc configuration

  string   IRC_Server         = CFG->GetString("irc_server", "irc.pvpgn.mobavietnam.com");
  string   IRC_NickName       = CFG->GetString("irc_nickname", "mobazbot" + to_string(m_HostPort));
  string   IRC_UserName       = CFG->GetString("irc_username", "mobazbot" + to_string(m_HostPort));
  string   IRC_Password       = CFG->GetString("irc_password", "b3APQdYe6ePwhc8X");
  string   IRC_CommandTrigger = CFG->GetString("irc_commandtrigger", "!");
  uint32_t IRC_Port           = CFG->GetInt("irc_port", 6667);

  // get the irc channels and root admins

  vector<string> IRC_Channels, IRC_RootAdmins;

  for (uint32_t i = 1; i <= 10; ++i)
  {
    string Channel, RootAdmin;

    if (i == 1)
    {
      Channel   = CFG->GetString("irc_channel", "mobazgame4");
      RootAdmin = CFG->GetString("irc_rootadmin", string());
    }
    else
    {
      Channel   = CFG->GetString("irc_channel" + to_string(i), string());
      RootAdmin = CFG->GetString("irc_rootadmin" + to_string(i), string());
    }

    if (!Channel.empty())
      IRC_Channels.push_back("#" + Channel);

    if (!RootAdmin.empty())
      IRC_RootAdmins.push_back(RootAdmin);
  }

  if (IRC_Server.empty() || IRC_NickName.empty() || IRC_Port == 0 || IRC_Port >= 65535)
    Print("[MobaZ] warning - irc connection not found in config file");
  else
    m_IRC = new CIRC(this, IRC_Server, IRC_NickName, IRC_UserName, IRC_Password, IRC_Channels, IRC_RootAdmins, IRC_Port, IRC_CommandTrigger[0]);

  string ServerF              = CFG->GetString("serverb", "45.122.221.212");
  uint32_t PortF             = CFG->GetInt("portb", 9000);
  m_Broadcast                   = new TCPBroadcast(ServerF, PortF);
  uint8_t HighestWar3Version = 0;

  // load the battle.net connections
  // we're just loading the config data and creating the CBNET classes here, the connections are established later (in the Update function)

  for (uint32_t i = 1; i < 2; ++i)
  {
    string Prefix;

    if (i == 1)
      Prefix = "bnet_";
    else
      Prefix = "bnet" + to_string(i) + "_";

    string   Server        = CFG->GetString(Prefix + "server", "pvpgn.local.com");
    string   ServerAlias   = CFG->GetString(Prefix + "serveralias", "mobaz");
    string   CDKeyROC      = CFG->GetString(Prefix + "cdkeyroc", "");
    string   CDKeyTFT      = CFG->GetString(Prefix + "cdkeytft", "");
    string   CountryAbbrev = CFG->GetString(Prefix + "countryabbrev", "DEU");
    string   Country       = CFG->GetString(Prefix + "country", "Germany");
    string   Locale        = CFG->GetString(Prefix + "locale", "system");
    uint32_t LocaleID;

    if (Locale == "system")
      LocaleID = 1031;
    else
      LocaleID = stoul(Locale);

    string UserName     = CFG->GetString(Prefix + "username", string());
    string UserPassword = CFG->GetString(Prefix + "password", string());
    string FirstChannel = CFG->GetString(Prefix + "firstchannel", "The Void");
    string RootAdmins   = CFG->GetString(Prefix + "rootadmins", string());

    // add each root admin to the rootadmin table

    string       User;
    stringstream SS;
    SS << RootAdmins;

    while (!SS.eof())
    {
      SS >> User;
      m_DB->RootAdminAdd(Server, User);
    }

    string               BNETCommandTrigger = CFG->GetString(Prefix + "commandtrigger", "!");
    uint8_t              War3Version        = CFG->GetInt(Prefix + "custom_war3version", 26);
    std::vector<uint8_t> EXEVersion         = ExtractNumbers(CFG->GetString(Prefix + "custom_exeversion", string()), 4);
    std::vector<uint8_t> EXEVersionHash     = ExtractNumbers(CFG->GetString(Prefix + "custom_exeversionhash", string()), 4);
    string               PasswordHashType   = CFG->GetString(Prefix + "custom_passwordhashtype", string());

    HighestWar3Version = (std::max)(HighestWar3Version, War3Version);

    if (Server.empty())
      break;

    Print("[MobaZ] found battle.net connection #" + to_string(i) + " for server [" + Server + "]");

    if (Locale == "system")
      Print("[MobaZ] using system locale of " + to_string(LocaleID));

    m_BNETs.push_back(new CBNET(this, Server, ServerAlias, CDKeyROC, CDKeyTFT, CountryAbbrev, Country, LocaleID, UserName, UserPassword, FirstChannel, BNETCommandTrigger[0], War3Version, EXEVersion, EXEVersionHash, PasswordHashType, i));
  }

  if (m_BNETs.empty())
    Print("[MobaZ] warning - no battle.net connections found in config file");

  if (m_BNETs.empty() && !m_IRC)
  {
    Print("[MobaZ] error - no battle.net connections and no irc connection specified");
    m_Ready = false;
    return;
  }

  // extract common.j and blizzard.j from War3Patch.mpq or War3.mpq (depending on version) if we can
  // these two files are necessary for calculating "map_crc" when loading maps so we make sure to do it before loading the default map
  // see CMap :: Load for more information

  ExtractScripts(HighestWar3Version);

  // load the default maps (note: make sure to run ExtractScripts first)

  if (m_DefaultMap.size() < 4 || m_DefaultMap.substr(m_DefaultMap.size() - 4) != ".cfg")
    m_DefaultMap += ".cfg";

  CConfig MapCFG;
  MapCFG.Read(m_MapCFGPath + m_DefaultMap);
  m_Map = new CMap(this, &MapCFG, m_MapCFGPath + m_DefaultMap);

  // load the iptocountry data

  LoadIPToCountryData();
}

CAura::~CAura()
{
  delete m_UDPSocket;
  delete m_CRC;
  delete m_SHA;
  delete m_ReconnectSocket;
  delete m_GPSProtocol;

  if (m_Map)
    delete m_Map;

  for (auto& socket : m_ReconnectSockets)
    delete socket;

  for (auto& bnet : m_BNETs)
    delete bnet;

  delete m_CurrentGame;

  for (auto& game : m_Games)
    delete game;

  delete m_DB;

  if (m_IRC)
    delete m_IRC;

  if (m_Broadcast)
    delete m_Broadcast;
}

bool CAura::Update()
{
  uint32_t NumFDs = 0;

  // take every socket we own and throw it in one giant select statement so we can block on all sockets

  int32_t nfds = 0;
  fd_set  fd, send_fd;
  FD_ZERO(&fd);
  FD_ZERO(&send_fd);

  // 1. the current game's server and player sockets

  if (m_CurrentGame)
    NumFDs += m_CurrentGame->SetFD(&fd, &send_fd, &nfds);

  // 2. all running games' player sockets

  for (auto& game : m_Games)
    NumFDs += game->SetFD(&fd, &send_fd, &nfds);

  // 3. all battle.net sockets

  for (auto& bnet : m_BNETs)
    NumFDs += bnet->SetFD(&fd, &send_fd, &nfds);

  // 4. irc socket

  if (m_IRC)
    NumFDs += m_IRC->SetFD(&fd, &send_fd, &nfds);

  if (m_Broadcast)
    NumFDs += m_Broadcast->SetFD(&fd, &send_fd, &nfds);

  // 5. reconnect socket

  if (m_ReconnectSocket->HasError())
  {
    Print("[MobaZ] GProxy++ reconnect listener error (" + m_ReconnectSocket->GetErrorString() + ")");
    return true;
  }
  else
  {
    m_ReconnectSocket->SetFD(&fd, &send_fd, &nfds);
    ++NumFDs;
  }

  // 6. reconnect sockets

  for (auto& socket : m_ReconnectSockets)
  {
    socket->SetFD(&fd, &send_fd, &nfds);
    ++NumFDs;
  }

  // before we call select we need to determine how long to block for
  // 50 ms is the hard maximum

  int64_t usecBlock = 50000;

  for (auto& game : m_Games)
  {
    if (game->GetNextTimedActionTicks() * 1000 < usecBlock)
      usecBlock = game->GetNextTimedActionTicks() * 1000;
  }

  struct timeval tv;
  tv.tv_sec  = 0;
  tv.tv_usec = static_cast<long int>(usecBlock);

  struct timeval send_tv;
  send_tv.tv_sec  = 0;
  send_tv.tv_usec = 0;

#ifdef WIN32
  select(1, &fd, nullptr, nullptr, &tv);
  select(1, nullptr, &send_fd, nullptr, &send_tv);
#else
  select(nfds + 1, &fd, nullptr, nullptr, &tv);
  select(nfds + 1, nullptr, &send_fd, nullptr, &send_tv);
#endif

  if (NumFDs == 0)
  {
    // we don't have any sockets (i.e. we aren't connected to battle.net and irc maybe due to a lost connection and there aren't any games running)
    // select will return immediately and we'll chew up the CPU if we let it loop so just sleep for 200ms to kill some time

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  bool Exit = false;

  // update running games

  for (auto i = begin(m_Games); i != end(m_Games);)
  {
    if ((*i)->Update(&fd, &send_fd))
    {
      Print2("[MobaZ] deleting game [" + (*i)->GetGameName() + "]");
      Print3("endgame", (*i)->GetCreatorName());
      EventGameDeleted(*i);
      delete *i;
      i = m_Games.erase(i);
    }
    else
    {
      (*i)->UpdatePost(&send_fd);
      ++i;
    }
  }

  // update current game

  if (m_CurrentGame)
  {
    if (m_CurrentGame->Update(&fd, &send_fd))
    {
      Print2("[MobaZ] deleting current game [" + m_CurrentGame->GetGameName() + "]");
      Print3("cancelgame", m_CurrentGame->GetOwnerName());
      m_CurrentGame->SendCancel();
      delete m_CurrentGame;
      m_CurrentGame = nullptr;

      for (auto& bnet : m_BNETs)
      {
        bnet->QueueGameUncreate();
        bnet->QueueEnterChat();
      }
    }
    else if (m_CurrentGame)
      m_CurrentGame->UpdatePost(&send_fd);
  }

  // update battle.net connections

  for (auto& bnet : m_BNETs)
  {
    if (bnet->Update(&fd, &send_fd))
      Exit = true;
  }

  // update irc

  if (m_IRC && m_IRC->Update(&fd, &send_fd))
    Exit = true;

    if (m_Broadcast && m_Broadcast->Update(&fd, &send_fd))
    Exit = true;
  // update GProxy++ reliable reconnect sockets

  CTCPSocket* NewSocket = m_ReconnectSocket->Accept(&fd);

  if (NewSocket)
    m_ReconnectSockets.push_back(NewSocket);

  for (auto i = begin(m_ReconnectSockets); i != end(m_ReconnectSockets);)
  {
    if ((*i)->HasError() || !(*i)->GetConnected() || GetTime() - (*i)->GetLastRecv() >= 10)
    {
      delete *i;
      i = m_ReconnectSockets.erase(i);
      continue;
    }

    (*i)->DoRecv(&fd);
    string*                    RecvBuffer = (*i)->GetBytes();
    const std::vector<uint8_t> Bytes      = CreateByteArray((uint8_t*)RecvBuffer->c_str(), RecvBuffer->size());

    // a packet is at least 4 bytes

    if (Bytes.size() >= 4)
    {
      if (Bytes[0] == GPS_HEADER_CONSTANT)
      {
        // bytes 2 and 3 contain the length of the packet

        const uint16_t Length = static_cast<uint16_t>(Bytes[3] << 8 | Bytes[2]);

        if (Bytes.size() >= Length)
        {
          if (Bytes[1] == CGPSProtocol::GPS_RECONNECT && Length == 13)
          {
            const uint32_t ReconnectKey = ByteArrayToUInt32(Bytes, false, 5);
            const uint32_t LastPacket   = ByteArrayToUInt32(Bytes, false, 9);

            // look for a matching player in a running game

            CGamePlayer* Match = nullptr;

            for (auto& game : m_Games)
            {
              if (game->GetGameLoaded())
              {
                CGamePlayer* Player = game->GetPlayerFromPID(Bytes[4]);

                if (Player && Player->GetGProxy() && Player->GetGProxyReconnectKey() == ReconnectKey)
                {
                  Match = Player;
                  break;
                }
              }
            }

            if (Match)
            {
              // reconnect successful!

              *RecvBuffer = RecvBuffer->substr(Length);
              Match->EventGProxyReconnect(*i, LastPacket);
              i = m_ReconnectSockets.erase(i);
              continue;
            }
            else
            {
              (*i)->PutBytes(m_GPSProtocol->SEND_GPSS_REJECT(REJECTGPS_NOTFOUND));
              (*i)->DoSend(&send_fd);
              delete *i;
              i = m_ReconnectSockets.erase(i);
              continue;
            }
          }
          else
          {
            (*i)->PutBytes(m_GPSProtocol->SEND_GPSS_REJECT(REJECTGPS_INVALID));
            (*i)->DoSend(&send_fd);
            delete *i;
            i = m_ReconnectSockets.erase(i);
            continue;
          }
        }
        else
        {
          (*i)->PutBytes(m_GPSProtocol->SEND_GPSS_REJECT(REJECTGPS_INVALID));
          (*i)->DoSend(&send_fd);
          delete *i;
          i = m_ReconnectSockets.erase(i);
          continue;
        }
      }
      else
      {
        (*i)->PutBytes(m_GPSProtocol->SEND_GPSS_REJECT(REJECTGPS_INVALID));
        (*i)->DoSend(&send_fd);
        delete *i;
        i = m_ReconnectSockets.erase(i);
        continue;
      }
    }

    (*i)->DoSend(&send_fd);
    ++i;
  }

  return m_Exiting || Exit;
}

void CAura::EventBNETGameRefreshFailed(CBNET* bnet)
{
  if (m_CurrentGame)
  {
    // If the game has someone in it, advertise the fail only in the lobby (as it is probably a rehost).
    // Otherwise whisper the game creator that the (re)host failed.

    if (m_CurrentGame->GetNumHumanPlayers() != 0)
      m_CurrentGame->SendAllChat("Unable to create game on server [" + bnet->GetServer() + "]. Try another name");
    else
      m_CurrentGame->GetCreatorServer()->QueueChatCommand("Unable to create game on server [" + bnet->GetServer() + "]. Try another name", m_CurrentGame->GetCreatorName(), true, string());

    Print2("[GAME: " + m_CurrentGame->GetGameName() + "] Unable to create game on server [" + bnet->GetServer() + "]. Try another name");

    // we take the easy route and simply close the lobby if a refresh fails
    // it's possible at least one refresh succeeded and therefore the game is still joinable on at least one battle.net (plus on the local network) but we don't keep track of that
    // we only close the game if it has no players since we support game rehosting (via !priv and !pub in the lobby)

    if (m_CurrentGame->GetNumHumanPlayers() == 0)
      m_CurrentGame->SetExiting(true);

    m_CurrentGame->SetRefreshError(true);
  }
}

void CAura::EventGameDeleted(CGame* game)
{
  for (auto& bnet : m_BNETs)
  {
    bnet->QueueChatCommand("Game [" + game->GetDescription() + "] is over");

    if (bnet == game->GetCreatorServer())
      bnet->QueueChatCommand("Game [" + game->GetDescription() + "] is over", game->GetCreatorName(), true, string());
  }
}

void CAura::ReloadConfigs()
{
  CConfig CFG;
  CFG.Read("aura.cfg");
  SetConfigs(&CFG);
}

void CAura::SetConfigs(CConfig* CFG)
{
  // this doesn't set EVERY config value since that would potentially require reconfiguring the battle.net connections
  // it just set the easily reloadable values

  m_Warcraft3Path          = AddPathSeparator(CFG->GetString("bot_war3path", "aura"));
  m_BindAddress            = CFG->GetString("bot_bindaddress", string());
  m_ReconnectWaitTime      = CFG->GetInt("bot_reconnectwaittime", 1);
  m_MaxGames               = CFG->GetInt("bot_maxgames", 10);
  string BotCommandTrigger = CFG->GetString("bot_commandtrigger", "!");
  m_CommandTrigger         = BotCommandTrigger[0];

  m_MapCFGPath      = AddPathSeparator(CFG->GetString("bot_mapcfgpath", "mapcfgs"));
  m_MapPath         = AddPathSeparator(CFG->GetString("bot_mappath", "maps"));
  m_VirtualHostName = CFG->GetString("bot_virtualhostname", "|cFF4080C0MobaZ");

  if (m_VirtualHostName.size() > 15)
  {
    m_VirtualHostName = "|cFF4080C0MobaZ";
    Print("[MobaZ] warning - bot_virtualhostname is longer than 15 characters, using default virtual host name");
  }

  m_AutoLock           = CFG->GetInt("bot_autolock", 0) == 0 ? false : true;
  m_AllowDownloads     = CFG->GetInt("bot_allowdownloads", 0);
  m_MaxDownloaders     = CFG->GetInt("bot_maxdownloaders", 3);
  m_MaxDownloadSpeed   = CFG->GetInt("bot_maxdownloadspeed", 100);
  m_LCPings            = CFG->GetInt("bot_lcpings", 1) == 0 ? false : true;
  m_AutoKickPing       = CFG->GetInt("bot_autokickping", 300);
  m_LobbyTimeLimit     = CFG->GetInt("bot_lobbytimelimit", 2);
  m_Latency            = CFG->GetInt("bot_latency", 100);
  m_SyncLimit          = CFG->GetInt("bot_synclimit", 50);
  m_VoteKickPercentage = CFG->GetInt("bot_votekickpercentage", 70);

  if (m_VoteKickPercentage > 100)
    m_VoteKickPercentage = 100;
}

void CAura::ExtractScripts(const uint8_t War3Version)
{
  void*        MPQ;
  const string MPQFileName = [&]() {
    if (War3Version >= 28)
      return m_Warcraft3Path + "War3.mpq";
    else
      return m_Warcraft3Path + "War3Patch.mpq";
  }();

#ifdef WIN32
  const wstring MPQFileNameW = [&]() {
    if (War3Version >= 28)
      return wstring(begin(m_Warcraft3Path), end(m_Warcraft3Path)) + _T("War3.mpq");
    else
      return wstring(begin(m_Warcraft3Path), end(m_Warcraft3Path)) + _T("War3Patch.mpq");
  }();

  if (SFileOpenArchive(MPQFileNameW.c_str(), 0, MPQ_OPEN_FORCE_MPQ_V1, &MPQ))
#else
  if (SFileOpenArchive(MPQFileName.c_str(), 0, MPQ_OPEN_FORCE_MPQ_V1, &MPQ))
#endif
  {
    Print("[MobaZ] loading MPQ file [" + MPQFileName + "]");
    void* SubFile;

    // common.j

    if (SFileOpenFileEx(MPQ, R"(Scripts\common.j)", 0, &SubFile))
    {
      const uint32_t FileLength = SFileGetFileSize(SubFile, nullptr);

      if (FileLength > 0 && FileLength != 0xFFFFFFFF)
      {
        auto  SubFileData = new int8_t[FileLength];
        DWORD BytesRead   = 0;

        if (SFileReadFile(SubFile, SubFileData, FileLength, &BytesRead, nullptr))
        {
          Print(R"([MobaZ] extracting Scripts\common.j from MPQ file to [)" + m_MapCFGPath + "common.j]");
          FileWrite(m_MapCFGPath + "common.j", reinterpret_cast<uint8_t*>(SubFileData), BytesRead);
        }
        else
          Print(R"([MobaZ] warning - unable to extract Scripts\common.j from MPQ file)");

        delete[] SubFileData;
      }

      SFileCloseFile(SubFile);
    }
    else
      Print(R"([MobaZ] couldn't find Scripts\common.j in MPQ file)");

    // blizzard.j

    if (SFileOpenFileEx(MPQ, R"(Scripts\blizzard.j)", 0, &SubFile))
    {
      const uint32_t FileLength = SFileGetFileSize(SubFile, nullptr);

      if (FileLength > 0 && FileLength != 0xFFFFFFFF)
      {
        auto  SubFileData = new int8_t[FileLength];
        DWORD BytesRead   = 0;

        if (SFileReadFile(SubFile, SubFileData, FileLength, &BytesRead, nullptr))
        {
          Print(R"([MobaZ] extracting Scripts\blizzard.j from MPQ file to [)" + m_MapCFGPath + "blizzard.j]");
          FileWrite(m_MapCFGPath + "blizzard.j", reinterpret_cast<uint8_t*>(SubFileData), BytesRead);
        }
        else
          Print(R"([MobaZ] warning - unable to extract Scripts\blizzard.j from MPQ file)");

        delete[] SubFileData;
      }

      SFileCloseFile(SubFile);
    }
    else
      Print(R"([MobaZ] couldn't find Scripts\blizzard.j in MPQ file)");

    SFileCloseArchive(MPQ);
  }
  else
  {
#ifdef WIN32
    Print("[MobaZ] warning - unable to load MPQ file [" + MPQFileName + "] - error code " + to_string((uint32_t)GetLastError()));
#else
    Print("[MobaZ] warning - unable to load MPQ file [" + MPQFileName + "] - error code " + to_string(static_cast<int32_t>(GetLastError())));
#endif
  }
}

void CAura::LoadIPToCountryData()
{
  ifstream in;
  in.open("ip-to-country.csv");

  if (in.fail())
    Print("[MobaZ] warning - unable to read file [ip-to-country.csv], iptocountry data not loaded");
  else
  {
    Print("[MobaZ] started loading [ip-to-country.csv]");

    // the begin and commit statements are optimizations
    // we're about to insert ~4 MB of data into the database so if we allow the database to treat each insert as a transaction it will take a LONG time

    if (!m_DB->Begin())
      Print("[MobaZ] warning - failed to begin database transaction, iptocountry data not loaded");
    else
    {
      uint8_t   Percent = 0;
      string    Line, Skip, IP1, IP2, Country;
      CSVParser parser;

      // get length of file for the progress meter

      in.seekg(0, ios::end);
      const uint32_t FileLength = in.tellg();
      in.seekg(0, ios::beg);

      while (!in.eof())
      {
        getline(in, Line);

        if (Line.empty())
          continue;

        parser << Line;
        parser >> Skip;
        parser >> Skip;
        parser >> IP1;
        parser >> IP2;
        parser >> Country;
        m_DB->FromAdd(stoul(IP1), stoul(IP2), Country);

        // it's probably going to take awhile to load the iptocountry data (~10 seconds on my 3.2 GHz P4 when using SQLite3)
        // so let's print a progress meter just to keep the user from getting worried

        uint8_t NewPercent = static_cast<uint8_t>((float)in.tellg() / FileLength * 100);

        if (NewPercent != Percent && NewPercent % 10 == 0)
        {
          Percent = NewPercent;
          Print("[MobaZ] iptocountry data: " + to_string(Percent) + "% loaded");
        }
      }

      if (!m_DB->Commit())
        Print("[MobaZ] warning - failed to commit database transaction, iptocountry data not loaded");
      else
        Print("[MobaZ] finished loading [ip-to-country.csv]");
    }

    in.close();
  }
}

void CAura::CreateGame(CMap* map, uint8_t gameState, string gameName, string ownerName, string creatorName, CBNET* creatorServer, bool whisper)
{
  if (!m_Enabled)
  {
    creatorServer->QueueChatCommand("noready", creatorName, whisper, ownerName);
    creatorServer->QueueChatCommand("Unable to create game [" + gameName + "]. The bot is disabled", creatorName, whisper, string());
    return;
  }

  if (gameName.size() > 31)
  {
    creatorServer->QueueChatCommand("Unable to create game [" + gameName + "]. The game name is too long (the maximum is 31 characters)", creatorName, whisper, string());
    return;
  }

  if (!map->GetValid())
  {
    creatorServer->QueueChatCommand("Unable to create game [" + gameName + "]. The currently loaded map config file is invalid", creatorName, whisper, string());
    return;
  }

  if (m_CurrentGame)
  {
    creatorServer->QueueChatCommand("noready", creatorName, whisper, ownerName);
    //creatorServer->QueueChatCommand("Unable to create game [" + gameName + "]. Another game [" + m_CurrentGame->GetDescription() + "] is in the lobby", creatorName, whisper, string());
    return;
  }

  if (m_Games.size() >= m_MaxGames)
  {
    creatorServer->QueueChatCommand("maxgame", creatorName, whisper, ownerName);
    //creatorServer->QueueChatCommand("Unable to create game [" + gameName + "]. The maximum number of simultaneous games (" + to_string(m_MaxGames) + ") has been reached", creatorName, whisper, string());
    return;
  }

  Print2("[MobaZ] creating game [" + gameName + "]");
  Print3("cready", ownerName);

  m_CurrentGame = new CGame(this, map, m_HostPort, gameState, gameName, ownerName, creatorName, creatorServer);

  for (auto& bnet : m_BNETs)
  {
    if (whisper && bnet == creatorServer)
    {
      // note that we send this whisper only on the creator server

      if (gameState == GAME_PRIVATE)
        bnet->QueueChatCommand("Creating private game [" + gameName + "] started by [" + ownerName + "]", creatorName, whisper, string());
      else
        bnet->QueueChatCommand("Creating public game [" + gameName + "] started by [" + ownerName + "]", creatorName, whisper, string());
    }
    else
    {
      // note that we send this chat message on all other bnet servers

      if (gameState == GAME_PRIVATE)
        bnet->QueueChatCommand("Creating private game [" + gameName + "] started by [" + ownerName + "]");
      else
        bnet->QueueChatCommand("Creating public game [" + gameName + "] started by [" + ownerName + "]");
    }

    bnet->QueueGameCreate(gameState, gameName, map, m_CurrentGame->GetHostCounter());

    // hold friends and/or clan members

    bnet->HoldFriends(m_CurrentGame);
    bnet->HoldClan(m_CurrentGame);

    // if we're creating a private game we don't need to send any game refresh messages so we can rejoin the chat immediately
    // unfortunately this doesn't work on PVPGN servers because they consider an enterchat message to be a gameuncreate message when in a game
    // so don't rejoin the chat if we're using PVPGN

    if (gameState == GAME_PRIVATE && !bnet->GetPvPGN())
      bnet->QueueEnterChat();
  }
}
