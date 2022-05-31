// © 2020 Erik Rigtorp <erik@rigtorp.se>
// SPDX-License-Identifier: MIT

// Changes from Qualcomm Innovation Center are provided under the following license:
// Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include <csignal>
#include <netdb.h>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <exception>

#define NANOSECONDS_PER_SECOND 1000000000L
#define MAX_UDP_PORT_RANGE 65535

int numSent;
int burst_packets_sent;
int total_intervals;
double avg_burst_rate;
double avgPerSec;


static void signalHandler(int signum) {
  std::cout << "Interrupt signal (" << signum << ") received.\n";
  if(total_intervals){
      std::cout << "Total packets sent during bursts is: "
          << numSent << "\n";
      std::cout << "Total intervals is: " << total_intervals << "\n";
      std::cout << "Average burst interval packet rate is: "
          << avg_burst_rate<< " packets / interval\n";
      std::cout << "Average packet rate is: "
          << avgPerSec << " packets / sec\n";
  }else if(numSent){
      std::cout << "Total packets successfully sent is: " <<
              numSent << "\n";
  }
  exit(1);
}

/* function to derive the ipv6 address of an interface */
int get_ipv6_addr(const char* ifaceName, struct in6_addr* v6_addr) {
  int result = -1;
  struct ifaddrs *ifap;
  struct ifaddrs *ifa;
  struct sockaddr_in6 *sockAddr;
  char addr[46] = {0};

  if (NULL == ifaceName) {
    return -1;
  }

  getifaddrs(&ifap);
  ifa = ifap;
  while (ifa) {
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
      sockAddr = (struct sockaddr_in6 *) ifa->ifa_addr;

      if (sockAddr && 0 == strcmp(ifaceName, ifa->ifa_name)) {
        getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
                    addr, sizeof(addr),NULL, 0, NI_NUMERICHOST);
        {
          std::cout << "iface=" << ifa->ifa_name << " addr=" << addr << std::endl;
          result = 0;
          memcpy(v6_addr, &sockAddr->sin6_addr, sizeof(struct in6_addr));
          break;
        }
      }
    }
     ifa = ifa->ifa_next;
  }

  if (ifap) {
    freeifaddrs(ifap);
  }
  return result;
}

/* function to determine if a time is withing specified time range */
bool isWithinTimeRange(timespec& startTime, timespec& endTime, timespec& nowTime){
  // has it passed the start of time range?
  if(!(startTime.tv_sec <= nowTime.tv_sec ||
             (startTime.tv_sec == nowTime.tv_sec &&
              startTime.tv_nsec <= nowTime.tv_nsec)))
      return false;
  // has it passed the end of the time range?
  if(!(endTime.tv_sec > nowTime.tv_sec ||
         (endTime.tv_sec == nowTime.tv_sec &&
          endTime.tv_nsec > nowTime.tv_nsec)))
      return false;
  // within time range
  return true;
}

/* function to calculate the seconds difference between two time structs */
long int sec_diff(timespec& time_1, timespec& time_2){
  return (time_1.tv_sec - time_2.tv_sec);
}

/* function to calculate the nanoseconds difference between two time structs */
long int nsec_diff(timespec& time_1, timespec& time_2){
  return (time_1.tv_nsec - time_2.tv_nsec);
}

/* function which will go through pcap files in directory with a given suffix */
int  fileNameUpdate( time_t *changeStart, char pcapFileNameArg[],
                    int pcapArrSize, char pcapDirNameArg[],
                   int fileCount, int pcapChangeDuration )
{
  time_t changeStop;
  time(&changeStop);
  if(difftime(changeStop, *changeStart)  > pcapChangeDuration )
  {
      time(changeStart);
      snprintf(pcapFileNameArg, pcapArrSize, "%s/pcap_%d.pcap",
                               pcapDirNameArg, fileCount);
      std::cout<<"Switched to pcap : "<< pcapFileNameArg<<std::endl;
      fileCount++;
  }
  return fileCount;
}

int main(int argc, char *argv[]) {
  std::signal(SIGINT, signalHandler);
  /* Packet transmission related parameters */
  int ifindex = 0;
  int loopback = 0;
  double speed = 1;
  int interval = -1; //millisec
  int nano_interval = -1; // nanosec
  double rate = 0.0;
  int repeat = 1;
  int ttl = -1;
  bool noWait = false;
  // following threshold should be adapted to architecture
  // X86 -> 5000 ns ; AARCH -> maybe 100 microsecs e.g. 100,000 nanosecs
  int nanoGapThresh = 5000;

  /* Source and destination communication parameters */
  int broadcast = 0;
  std::string dest_ipv4 = "";
  std::string dest_ipv6 = "";
  std::string iface = "";
  int src_port = 0;
  int dest_port = 0;

  /* Burst mode related parameters */
  int burst_size = -1; // number of packets within burst
  int burstInterval = -1; //nanosec
  int burstGap = -1; //nanosec
  int burstIntervalGap = -1; //nanosec
  bool burstOn = false;

  /* PCAP file reading parameters */
  int fileCount = 0;
  int pcapChangeDuration=60; // default 60 s
  char pcapDirName[51];
  char pcapFileName[101];
  bool replacePcapDir=false;
  time_t changeStart;
  struct stat pcapStat;

  int opt;
  int ctr=0;
  try{
    while ((opt = getopt(argc, argv, "i:a:bls:c:n:r:t:d:g:p:j:R:")) != -1) {
      switch (opt) {
      case 'i':
        iface = (optarg);
        if (!iface.empty()) {
          std::cout << "iface name: " << iface << std::endl;
          ifindex = if_nametoindex(iface.data());
        }else{
          std::cerr << "if_nametoindex: " << strerror(errno) << std::endl;
          return 1;
        }
        if (ifindex == 0){
          std::cerr << "if_nametoindex: " << strerror(errno) << std::endl;
        }
        break;
      case 'a':
        src_port = std::stoi(optarg);
        if ((src_port <= 0) || (src_port > MAX_UDP_PORT_RANGE)) {
          std::cerr << "Invalid port number." << std::endl;
          return 1;
        }
        std::cout << "Attempting to send via source port :" << src_port << std::endl;
        break;
      case 'l':
        loopback = 1;
        break;
      case 's':
        speed = std::stod(optarg);
        if (speed < 0) {
          std::cerr << "speed must be positive" << std::endl;
        }
        break;
      case 'c':
        interval = std::stoi(optarg);
        if (interval <= 0) {
          std::cerr << "interval must be non-negative integer" << std::endl;
          return 1;
        }
        if (interval > 1000) {
          std::cerr << "interval must be less than or equal to 1000 msec" << std::endl;
          return 1;
        }
        rate = (double)interval/1000.0;
        std::cout << "Packets will be sent with interval of " << interval <<
                      " ms or " << rate << " s \n";
        std::cout << "Rate will be " << (1.0/rate) << " packets / sec \n";
        break;
      case 'n':
        nano_interval = std::stoi(optarg);
        if(nano_interval <= 0) {
          std::cerr << "nanosec interval must be non-negative integer" << std::endl;
          return 1;
        }
        // handle intervals that are too small; send as fast as possible
        if(nano_interval <= nanoGapThresh){
          noWait = true;
          std::cout << "Specified nanosec interval is too small.\n"
                       "Will attempt to send as fast as possible.\n";
        }else{
          rate = (double)nano_interval/(double)NANOSECONDS_PER_SECOND;
          std::cout << "Packets will be sent with interval of " << nano_interval <<
                      " ns or " << rate << " s \n";
          std::cout << "Rate will be " << (1.0/rate) << " packets / sec \n";
        }
        break;
      case 'r':
        repeat = std::stoi(optarg);
        if (repeat != -1 && repeat <= 0) {
          std::cerr << "repeat must be positive integer or -1" << std::endl;
          return 1;
        }
        break;
      case 't':
        ttl = std::stoi(optarg);
        if (ttl < 0) {
          std::cerr << "ttl must be non-negative integer" << std::endl;
          return 1;
        }
        break;
      case 'b':
        broadcast = 1;
        break;
      case 'd':
        std::cout << "Will attempt to send to ipv4 address: " << optarg << "\n";
        dest_ipv4 = (optarg);
        break;
      case 'g':
        std::cout << "Will attempt to send to ipv6 address: " << optarg << "\n";
        dest_ipv6 = (optarg);
        break;
      case 'p':
        dest_port = std::stoi(optarg);
        if ((dest_port <= 0) || (dest_port > MAX_UDP_PORT_RANGE)) {
          std::cerr << "Invalid port number." << std::endl;
          return 1;
        }
        std::cout << "Attempting to send to destination port :"
                      << dest_port << std::endl;
        break;
      case 'j':
        optind--;
       // go through next three arguments (if they exist)
        for( ;optind < argc-1 && *argv[optind] != '-' ; optind++){
          if(ctr==0){
            burstInterval = std::stoi(argv[optind]);
          }
          else if(ctr == 1){
            burstGap = std::stoi(argv[optind]);
          }
          else{
            burstIntervalGap = std::stoi(argv[optind]);
          }
          ctr++;
        }
        if(burstInterval == -1 || burstGap == -1 || burstIntervalGap  == -1){
          std::cerr << "Missing an argument for burst mode. \n";
          return 1;
        }
        burstOn = true;
        burst_size = burstInterval / burstGap;
        std::cout << "Burst interval will be: " << burstInterval << " nanoseconds \n";
        std::cout << "Burst gap will be: " << burstGap << " nanoseconds \n";
        std::cout << "Avg number of packets within burst interval should be around " <<
                   burst_size << "\n";
        std::cout << "Constant gap between burst interval will be: " <<
                   burstIntervalGap << " nanoseconds \n aka " << std::setprecision(9) <<
                   ((double)burstIntervalGap / (double) NANOSECONDS_PER_SECOND ) << " seconds\n";
        std::cout << "Total time of interval and interval gap is: " <<
                  (double)(burstIntervalGap + burstInterval) << " nanoseconds \n";
        std::cout << "Total intervals per sec will be: " <<
                 ((double)(1000000000.0)/
                   ((double) (burstInterval + burstIntervalGap))) << "\n";
        std::cout << "Total number of packets per sec will be: " <<
                 ((double)(1000000000.0)/
                  ((double) (burstInterval + burstIntervalGap)) * burst_size) << "\n";
        // handle intervals that are too small ; send as fast as possible
        if(burstGap <= nanoGapThresh){
          noWait = true;
          std::cout << "Specified nanosec interval is too small.\n"
                       "Will attempt to send as fast as possible.\n";
        }

        break;
      case 'R':
         strlcpy(pcapDirName,optarg, sizeof(pcapDirName)-1);
         if( !( stat(pcapDirName,&pcapStat) == 0 && S_ISDIR(pcapStat.st_mode) ) ) {
           std::cerr<<"Directory "<<pcapDirName<<" doesn't exist."<<std::endl;
           return 1;
         }
         std::cout<<"Pcap changing opted from the directory "<<pcapDirName<<std::endl;
         if(argv[optind])  {
        // determine if duration has been provided
           if( argv[optind][0]  != '-' && isdigit(argv[optind][0]) ) {
             pcapChangeDuration=std::stoi(argv[optind]);
             optind++;
             std::cout<<"Each pcap will be played "<<pcapChangeDuration
                                                   <<" seconds" <<std::endl;
           }
           else
           {
             std::cerr<<"Duration should be a integer."<<std::endl;
             return 1;
           }
         }
         else {
           std::cerr<<"Duration is missing."<<std::endl;
           return 1;
         }
         replacePcapDir=true;
         break;
      default:
         goto usage;
      }
    }
  }
  catch(std::exception &err){
   std::cerr << "Exception caught: " << err.what() << "\n";
   return 1;
  }
  if (optind >= argc) {
  usage:
    std::cerr
        << "udpreplay 1.0.0 © 2020 Erik Rigtorp <erik@rigtorp.se> "
           "https://github.com/rigtorp/udpreplay\n"
           "usage: udpreplay "
           "[-i iface] [-a src port] [-l] [-s speed] [-c millisec] [-n nanosec]\n"
           "[-r repeat] [-t ttl] [-d dest ipv4] [-g dest ipv6] [-p dest port]\n"
           "[-j burst_gap burst_interval time_between_burst_interval] "
           "pcap\n"
           "\n"
           "  -i iface    interface to send packets through\n"
           "  -a          source port number\n"
           "  -l          enable loopback\n"
           "  -c millisec constant milliseconds between packets\n"
           "  -n nanosec constant nanoseconds between packets\n"
           "  -r repeat   number of times to loop data (-1 for infinite loop)\n"
           "  -s speed    replay speed relative to pcap timestamps\n"
           "  -t ttl      packet ttl\n"
           "  -b          enable broadcast (SO_BROADCAST)\n"
           "  -d          destination ipv4 address\n"
           "  -g          destination ipv6 address\n"
           "  -p          destination port number\n"
           "  -j  [constant time gap between each packet in data burst interval] \n"
           "      [total time interval of data burst] \n"
           "      [constant gap between each data burst interval] \n"
           "  -R  [Path to Directory where pcap to replace is present \n"
           "      (pcap shuld be in form pcap_[index].pcap)] \n"
           "      [Duration for each pcap to be played] \n"
        << std::endl;
    return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  // modify the socket if ipv6 address is specified
  if(!dest_ipv6.empty())
      fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return 1;
  }

  if (ifindex != 0) {
    ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) ==
        -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (loopback != 0) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback,
                   sizeof(loopback)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (broadcast != 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                   sizeof(broadcast)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (ttl != -1) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  /* Initialize time related variables */
  timespec now = {};
  timespec deadline = {};
  if(!burstOn){
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
      std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
      return 1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
      std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  /* Burst packet transmission related parameters */
  timespec burst_deadline = {};
  timespec burst_start = {};
  timespec burst_end = {};
  if(burstOn){
    // changing the order of these will cause different program behavior
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
      std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
      return 1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &burst_end) == -1) {
      std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
      return 1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &burst_start) == -1) {
      std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
      return 1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &burst_deadline) == -1) {
      std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
      return 1;
    }
    burst_end.tv_nsec += burstInterval;
    if (burst_end.tv_nsec > NANOSECONDS_PER_SECOND) {
      burst_end.tv_sec++;
      burst_end.tv_nsec -= NANOSECONDS_PER_SECOND;
    }
  }

  /* Set the source port */
  if (src_port > 0) {
    // Allow multiple clients to bind to same port
    int option = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
            (void *)(&option), sizeof(option)) < 0) {
      std::cerr << "SO_REUSEPORT: " << strerror(errno) << std::endl;
    }

    if (!iface.empty() && !dest_ipv6.empty()) {
      struct sockaddr_in6 src_addr_v6;
      memset(&src_addr_v6, 0, sizeof(sockaddr_in6));
      if (0 != get_ipv6_addr(iface.c_str(), &src_addr_v6.sin6_addr)) {
        std::cerr << "get_ipv6_addr error" << std::endl;
        return -2;
      }
      src_addr_v6.sin6_family = AF_INET6;
      src_addr_v6.sin6_port = htons(src_port);
      src_addr_v6.sin6_scope_id = ifindex;

      if (bind(fd,
        (struct sockaddr*)(&src_addr_v6), sizeof(struct sockaddr_in6)) < 0) {
          std::cerr << "bind: " << strerror(errno) << std::endl;
          return -1;
      }
    } else {
      struct sockaddr_in src_addr_v4;
      memset(&src_addr_v4, 0, sizeof(sockaddr_in));
      src_addr_v4.sin_family = AF_INET;
      src_addr_v4.sin_port = htons(src_port);
      if (bind(fd, (const struct sockaddr*)(&src_addr_v4),
                    sizeof(src_addr_v4)) < 0){
        std::cerr << "bind: " << strerror(errno) << std::endl;
        return -1;
      }
    }
  }

  // ipv4 destination address struct (if used)
  sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;

  // ipv6 destination address  (if used)
  struct sockaddr_in6 addr_ipv6;
  memset(&addr_ipv6, 0, sizeof(addr_ipv6));
  addr_ipv6.sin6_family = AF_INET6;

  /* Begin sending packets from pcap */
  time(&changeStart);
  strlcpy(pcapFileName,argv[optind],sizeof(pcapFileName)-1);
  for (int i = 0; repeat == -1 || i < repeat; i++) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // check if it is needed to go through pcaps in a provided directory
    if ( replacePcapDir ) {
       fileCount = fileNameUpdate(&changeStart, pcapFileName, sizeof(pcapFileName),
                                    pcapDirName, fileCount, pcapChangeDuration );
       if ( stat( pcapFileName, &pcapStat ) != 0  ) {
         if( fileCount == 1 ) {
           std::cout<<"Directory "<<pcapDirName<<" doesn't seems to have pcap_0.pcap.\
                    Please ensure your directory has pcaps in format pcap_[index].pcap\
                                                                starting form 0."<<std::endl;
         }
         else {
           std::cout<<"Replayed all the pcaps in the directoy. Exiting udpreplay."<<std::endl;
         }
         return 1;
       }
    }

    pcap_t *handle = pcap_open_offline_with_tstamp_precision(
        pcapFileName, PCAP_TSTAMP_PRECISION_NANO, errbuf);

    if (handle == nullptr) {
      std::cerr << "pcap_open: " << errbuf << std::endl;
      return 1;
    }

    timespec start = {-1, -1};
    timespec pcap_start = {-1, -1};

    pcap_pkthdr header;
    const u_char *p;
    while ((p = pcap_next(handle, &header))) {
       if (start.tv_nsec == -1) {
         if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
          std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
          return 1;
        }
        pcap_start.tv_sec = header.ts.tv_sec;
        pcap_start.tv_nsec =
            header.ts.tv_usec; // Note PCAP_TSTAMP_PRECISION_NANO
      }
      if (header.len != header.caplen) {
        continue;
      }
      auto eth = reinterpret_cast<const ether_header *>(p);

      // jump over and ignore vlan tags
      while (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
        p += 4;
        eth = reinterpret_cast<const ether_header *>(p);
      }
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        continue;
      }
      auto ip = reinterpret_cast<const struct ip *>(p + sizeof(ether_header));
      if (ip->ip_v != 4) {
        continue;
      }
      if (ip->ip_p != IPPROTO_UDP) {
        continue;
      }
      auto udp = reinterpret_cast<const udphdr *>(p + sizeof(ether_header) +
                                                  ip->ip_hl * 4);

      // check if requested time settings is not possible (based on threshold)
      // if the specified nanosec interval is too small, send as fast as possible
      if(!noWait){

        // get the current time
        if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
          std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
          return 1;
        }

        /* determine next time to do a burst and when it will end
         * during bursts, use the burst gap instead of normal gap
         * when burst interval is completed, perform no messages
         * repeat
         */
        // burst will not be used
        if(!burstOn){
          if(interval != -1){ // millisec precision
            // Use constant packet rate
            deadline.tv_sec += interval / 1000L;
            deadline.tv_nsec += (interval * 1000000L) % NANOSECONDS_PER_SECOND;
          }else if(nano_interval != -1){ // nanosec precision
            // Use constant packet rate
            deadline.tv_sec += nano_interval / 1000000000L;
            deadline.tv_nsec += (nano_interval * 1L) % NANOSECONDS_PER_SECOND;
          }else{ // packet-based timing
            // Next packet deadline = start + (packet ts - first packet ts) * speed
            int64_t delta =
              (header.ts.tv_sec - pcap_start.tv_sec) * NANOSECONDS_PER_SECOND +
               (header.ts.tv_usec -
               pcap_start.tv_nsec); // Note PCAP_TSTAMP_PRECISION_NANO
            if (speed != 1.0) {
              delta *= speed;
            }
            deadline = start;
            deadline.tv_sec += delta / NANOSECONDS_PER_SECOND;
            deadline.tv_nsec += delta % NANOSECONDS_PER_SECOND;
          }

          // Normalize timespec
          if (deadline.tv_nsec > NANOSECONDS_PER_SECOND) {
            deadline.tv_sec++;
            deadline.tv_nsec -= NANOSECONDS_PER_SECOND;
          }
           // Use non-burst mode deadline
          if (deadline.tv_sec > now.tv_sec ||
            (deadline.tv_sec == now.tv_sec &&
            deadline.tv_nsec > now.tv_nsec)) {
            if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline,
                            nullptr) == -1) {
              std::cerr << "clock_nanosleep: " << strerror(errno) << std::endl;
              return 1;
            }
          }
        }
        // burst mode is on
        else{
          if (burst_deadline.tv_sec > now.tv_sec ||
                (burst_deadline.tv_sec == now.tv_sec &&
                 burst_deadline.tv_nsec > now.tv_nsec)) {
            if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &burst_deadline,
                            nullptr) == -1) {
               std::cerr << "clock_nanosleep: " << strerror(errno) << std::endl;
               return 1;
            }
          }

          burst_deadline.tv_nsec += burstGap;
          if (burst_deadline.tv_nsec > NANOSECONDS_PER_SECOND) {
            burst_deadline.tv_sec++;
            burst_deadline.tv_nsec -= NANOSECONDS_PER_SECOND;
          }
        }

        // handle burst message option
        if(burstOn){
        // determine next time interval to send bursts
          if(numSent >= burst_size && (now.tv_sec > burst_end.tv_sec ||
                (now.tv_sec == burst_end.tv_sec &&
                 now.tv_nsec + burstGap >= burst_end.tv_nsec))){

           // statistics related to burst mode
            total_intervals++;
            avg_burst_rate = (double)((double)(numSent)/
                                      (double)(total_intervals));
            avgPerSec =  avg_burst_rate / (((double)burstIntervalGap + burstInterval)
                                   / NANOSECONDS_PER_SECOND);

            burst_start.tv_sec = burst_end.tv_sec;
            burst_start.tv_nsec = burst_end.tv_nsec + burstIntervalGap;
            // Normalize timespec
            if (burst_start.tv_nsec > NANOSECONDS_PER_SECOND) {
              burst_start.tv_sec++;
              burst_start.tv_nsec -= NANOSECONDS_PER_SECOND;
            }
            // update next burst end time only when burst has finished
            burst_end.tv_sec =
                           burst_start.tv_sec;
            burst_end.tv_nsec = burst_start.tv_nsec + burstInterval;
            // Normalize timespec
            if (burst_end.tv_nsec > NANOSECONDS_PER_SECOND) {
              burst_end.tv_sec++;
              burst_end.tv_nsec -= NANOSECONDS_PER_SECOND;
            }
            // sleep until next burst interval
            if (burst_start.tv_sec > now.tv_sec ||
                (burst_start.tv_sec == now.tv_sec &&
                 burst_start.tv_nsec > now.tv_nsec)) {
              if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &burst_start,
                            nullptr) == -1) {
                 std::cerr << "clock_nanosleep: " << strerror(errno) << std::endl;
                 return 1;
              }
              burst_deadline.tv_sec = burst_start.tv_sec;
              burst_deadline.tv_nsec = burst_start.tv_nsec+ burstGap;
              if (burst_deadline.tv_nsec > NANOSECONDS_PER_SECOND) {
                burst_deadline.tv_sec++;
                burst_deadline.tv_nsec -= NANOSECONDS_PER_SECOND;
              }
   /*        // update the timing for current packet if necessary
              // get the current time
              if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
                std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
                return 1;
              }

              if (burst_deadline.tv_sec < now.tv_sec ||
                    (burst_deadline.tv_sec == now.tv_sec &&
                     burst_deadline.tv_nsec <= now.tv_nsec)) {
                burst_deadline.tv_nsec += burstGap;
                if (burst_deadline.tv_nsec > NANOSECONDS_PER_SECOND) {
                  burst_deadline.tv_sec++;
                  burst_deadline.tv_nsec -= NANOSECONDS_PER_SECOND;
                }
              }*/
            }
          }
        }
      }

#ifdef __GLIBC__
      ssize_t len = ntohs(udp->len) - 8;
#else
      ssize_t len = ntohs(udp->uh_ulen) - 8;
#endif
      const u_char *d =
        &p[sizeof(ether_header) + ip->ip_hl * 4 + sizeof(udphdr)];

      // ipv6 destination address will be used
      if(!dest_ipv6.empty()){
        // check if destination port is provided
        if(dest_port > 0) {
          addr_ipv6.sin6_port = htons(dest_port);
        } else {
          addr_ipv6.sin6_port = udp->uh_dport;
        }
        inet_pton(AF_INET6, dest_ipv6.data(), &(addr_ipv6.sin6_addr));
        auto n = sendto(fd, d, len, 0,
                        reinterpret_cast<sockaddr *>(&addr_ipv6),
                        sizeof(addr_ipv6));
        if (n != len) {
          std::cerr << "sendto: " << strerror(errno) << std::endl;
          return 1;
        }else{
          numSent++;
        }
      }else{
      // ipv4 destination address will be used

#ifdef __GLIBC__
        // check if destination port is provided
        if(dest_port > 0) {
          addr.sin_port = htons(dest_port);
        } else {
          addr.sin_port = udp->dest;
        }
#else
        // check if destination port is provided
        if(dest_port > 0) {
          addr.sin_port = htons(dest_port);
        } else {
          addr.sin_port = udp->uh_dport;
        }
#endif

        // use provided ipv4 destination address
        if(!dest_ipv4.empty()){
          inet_pton(AF_INET, dest_ipv4.data(), &(addr.sin_addr));
        }else{
          // no ipv4 addresses provided, so original dest addr used
          addr.sin_addr = {ip->ip_dst};
        }

        auto n = sendto(fd, d, len, 0, reinterpret_cast<sockaddr *>(&addr),
                    sizeof(addr));
        if (n != len) {
          std::cerr << "sendto: " << strerror(errno) << std::endl;
          return 1;
        }else{
          numSent++;
        }
      }

      if ( replacePcapDir ) {
            int temp_filecount = fileCount;
            fileCount = fileNameUpdate(&changeStart, pcapFileName,
                        sizeof(pcapFileName), pcapDirName, fileCount, pcapChangeDuration );
        if (temp_filecount != fileCount ) {
          break;
        }
      }

    }
    pcap_close(handle);
  }
  return 0;
}
