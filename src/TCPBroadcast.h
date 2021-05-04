#pragma once
#include <vector>
#include <string>
#include <cstdint>

class CTCPClient;

class TCPBroadcast
{
public:
  CTCPClient*              m_Socket;
  std::string              m_Server;
  std::string              m_ServerIP;
  int64_t                  m_LastConnectionAttemptTime;
  int64_t                  m_LastPacketTime;
  int64_t                  m_LastAntiIdleTime;
  uint16_t                 m_Port;
  int8_t                   m_CommandTrigger;
  bool                     m_Exiting;
  bool                     m_WaitingToConnect;
  bool                     m_OriginalNick;

  TCPBroadcast(std::string nServer, uint16_t nPort);
  ~TCPBroadcast();
  TCPBroadcast(TCPBroadcast&) = delete;

  uint32_t SetFD(void* fd, void* send_fd, int32_t* nfds);
  void     ExtractPackets();
  bool     Update(void* fd, void* send_fd);
  void     SendData(const std::vector<uint8_t>& data);
};