/*
 *      mplstun.h
 *
 *      Copyright 2010 Daniel Mende <dmende@ernw.de>
 */

/*
 *      Redistribution and use in source and binary forms, with or without
 *      modification, are permitted provided that the following conditions are
 *      met:
 *      
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *      * Neither the name of the  nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *      
 *      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *      A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *      OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *      LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MPLSTUN_H
#define MPLSTUN_H 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <config.h>

#ifdef HAVE_NETINET_ETHER_H
 #include <netinet/ether.h>
 #define ETH_OCTET(x) ((x)->ether_addr_octet)
#else
 #ifdef HAVE_NET_ETHERNET_H
  #include <net/ethernet.h>
  #define ETH_OCTET(x) ((x)->octet)
  #ifndef ETH_ALEN
   #define ETH_ALEN ETHER_ADDR_LEN
  #endif
 #else
  #error ### no usable ethernet header file found ###
 #endif
#endif

#ifdef HAVE_LINUX_IF_H
 #include <linux/if.h>
 #ifdef HAVE_LINUX_IF_TUN_H
  #include <linux/if_tun.h>
  #define USE_LINUX_TUN 1
 #else
  #error ### linux/if_tun.h missing ###
 #endif
#else
 #ifdef HAVE_NET_IF_H
  #include <net/if.h>
  #define USE_BSD_TUN 1
 #endif
#endif


#include <dnet.h>
#include <pcap.h>

#define READ_BUFFER_SIZE 1600
#define WRITE_BUFFER_SIZE 1600
#define PCAP_FILTER_LENGTH 1024
#define TUN_DEV_NAME_LENGTH 32
#define MAX_TUN_NR 100

#define CHECK_FOR_LOCKFILE 1000
#define TIMEOUT_SEC 1
#define TIMEOUT_USEC 0

#define max(a,b) ((a)>(b) ? (a):(b))
#define min(a,b) ((a)>(b) ? (b):(a))
#define abs(a) ((a)<0 ? ((a)*-1):(a))

typedef enum e_tun_mode { NONE_TUN, L2_TUN, L3_TUN } tun_mode;

extern int mplstun(tun_mode, char*, char*, uint16_t, uint16_t, char*, char*, uint16_t, uint16_t, char*);
extern int mplstun_v(tun_mode, char*, char*, uint16_t, uint16_t, char*, char*, uint16_t, uint16_t, char*, int);

#endif
