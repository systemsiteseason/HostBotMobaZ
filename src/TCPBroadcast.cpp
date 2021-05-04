#include "TCPBroadcast.h"
#include "socket.h"
#include "util.h"
#include "bnetprotocol.h"
#include "bnet.h"

#include <utility>
#include <algorithm>

using namespace std;

//////////////////////
//// TCPBroadcast ////
//////////////////////

TCPBroadcast::TCPBroadcast(string nServer, uint16_t nPort)
  : m_Socket(new CTCPClient),
    m_Server(std::move(nServer)),
    m_LastConnectionAttemptTime(0),
    m_LastPacketTime(GetTime()),
    m_LastAntiIdleTime(GetTime()),
    m_Port(nPort),
    m_Exiting(false),
    m_WaitingToConnect(true)
{
}

TCPBroadcast::~TCPBroadcast()
{
  delete m_Socket;
}

uint32_t TCPBroadcast::SetFD(void* fd, void* send_fd, int32_t* nfds)
{
  // tcpbroadcast socket

  if (!m_Socket->HasError() && m_Socket->GetConnected())
  {
    m_Socket->SetFD(static_cast<fd_set*>(fd), static_cast<fd_set*>(send_fd), nfds);
    return 0;
  }

  return 1;
}

bool TCPBroadcast::Update(void* fd, void* send_fd)
{
  const int64_t Time = GetTime();

  if (m_Socket->HasError())
  {
    // the socket has an error

    Print("[Broadcast: " + m_Server + "] disconnected due to socket error,  waiting 60 seconds to reconnect");
    m_Socket->Reset();
    m_WaitingToConnect          = true;
    m_LastConnectionAttemptTime = Time;
    return m_Exiting;
  }

  if (m_Socket->GetConnected())
  {
    // the socket is connected and everything appears to be working properly

    if (Time - m_LastPacketTime > 210)
    {
      Print("[Broadcast: " + m_Server + "] ping timeout,  reconnecting");
      m_Socket->Reset();
      m_WaitingToConnect = true;
      return m_Exiting;
    }

    if (Time - m_LastAntiIdleTime > 60)
    {
      SendData(std::vector<uint8_t>{});
      m_LastAntiIdleTime = Time;
    }
    m_Socket->DoRecv(static_cast<fd_set*>(fd));
    ExtractPackets();
    m_Socket->DoSend(static_cast<fd_set*>(send_fd));
    return m_Exiting;
  }

  if (!m_Socket->GetConnecting() && !m_Socket->GetConnected() && !m_WaitingToConnect)
  {
    // the socket was disconnected

    Print("[Broadcast: " + m_Server + "] disconnected, waiting 60 seconds to reconnect");
    m_Socket->Reset();
    m_WaitingToConnect          = true;
    m_LastConnectionAttemptTime = Time;
    return m_Exiting;
  }

  if (m_Socket->GetConnecting())
  {
    // we are currently attempting to connect to irc

    if (m_Socket->CheckConnect())
    {
     // SendIRC("NICK " + m_Nickname);
      //SendIRC("USER " + m_Username + " " + m_Nickname + " " + m_Username + " :aura-bot");

      m_Socket->DoSend(static_cast<fd_set*>(send_fd));

      Print("[Broadcast: " + m_Server + "] connected");

      m_LastPacketTime = Time;

      return m_Exiting;
    }
    else if (Time - m_LastConnectionAttemptTime > 15)
    {
      // the connection attempt timed out (15 seconds)

      Print("[Broadcast: " + m_Server + "] connect timed out, waiting 60 seconds to reconnect");
      m_Socket->Reset();
      m_LastConnectionAttemptTime = Time;
      m_WaitingToConnect          = true;
      return m_Exiting;
    }
  }

  if (!m_Socket->GetConnecting() && !m_Socket->GetConnected() && (Time - m_LastConnectionAttemptTime > 60))
  {
    // attempt to connect to irc

    Print("[Broadcast: " + m_Server + "] connecting to server [" + m_Server + "] on port " + to_string(m_Port));

    if (m_ServerIP.empty())
    {
      m_Socket->Connect(string(), m_Server, m_Port);

      if (!m_Socket->HasError())
      {
        m_ServerIP = m_Socket->GetIPString();
      }
    }
    else
    {
      // use cached server IP address since resolving takes time and is blocking

      m_Socket->Connect(string(), m_ServerIP, m_Port);
    }

    m_WaitingToConnect          = false;
    m_LastConnectionAttemptTime = Time;
  }

  return m_Exiting;
}

void TCPBroadcast::ExtractPackets()
{
  const int64_t Time = GetTime();
  m_LastPacketTime = Time;
  m_Socket->ClearRecvBuffer();
}

void TCPBroadcast::SendData(const vector<uint8_t>& data)
{
  if (m_Socket->GetConnected())
    m_Socket->PutBytes(data);
}