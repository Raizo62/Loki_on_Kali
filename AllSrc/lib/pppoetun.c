/*
 *      pppoetun.c
 *
 *      Copyright 2014 Daniel Mende <dmende@ernw.de>
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

#include <arpa/inet.h>

#include <pppoetun.h>

int tun_alloc(char *tun_device) {
    int fd = -1;
    int err;
    struct ifreq ifr;

#ifdef USE_LINUX_TUN
    char *dev;
    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
        return -1;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    dev = "tun%d";
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    
    err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if( err < 0 ) {
         close(fd);
         return err;
    }
    strncpy(tun_device, ifr.ifr_name, TUN_DEV_NAME_LENGTH);

   ioctl(fd, TUNSETNOCSUM, 1);
#endif

#ifdef USE_BSD_TUN
    int i;
    char tunname[128];

    sprintf(tunname, "/dev/tun%d", i);

    for( i = 0; i < MAX_TUN_NR; i++ ) {        
        if( (fd = open(tunname, O_RDWR)) != -1 ) {
            
            break;
        }
    }

    if(fd < 0)
        return -1;

    strncpy(tun_device, tunname, TUN_DEV_NAME_LENGTH);
#endif

    return fd;
}


int pppoetun(char *in_device, char *out_device, uint16_t session_id, char *in_mac, char *out_mac, char *lock_file)
{
    return pppoetun_v(in_device, out_device, session_id, in_mac, out_mac, lock_file, 0);
}

int pppoetun_v(char *in_device, char *out_device, uint16_t session_id, char *in_mac, char *out_mac, char *lock_file, int verbose)
{
    eth_t *dnet_handle;
    pcap_t *pcap_handle;
    int tun_fd;

    unsigned char in[READ_BUFFER_SIZE];
    unsigned char out[WRITE_BUFFER_SIZE];
    int pcap_fd,l,len,fm;
    fd_set fds;

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pcap_packet;
    char filter[PCAP_FILTER_LENGTH];
    struct pcap_pkthdr *pcap_header;
    struct bpf_program pcap_filter;
    
    char tun_device[TUN_DEV_NAME_LENGTH];
    
    struct ether_header *eheader;
    unsigned char *start;
    int run, ret;
    struct stat fcheck;
    struct timeval timeout;

    tun_fd = tun_alloc(tun_device);
    if (tun_fd < 0) {
        fprintf(stderr, "Couldnt't create tunnel device: %s\n", strerror(errno));
        return 2;
    }
    if (verbose)
        printf("Tunnel interface %s created\n", tun_device);

    pcap_handle = pcap_create(in_device, pcap_errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    
    if (pcap_set_promisc(pcap_handle, 1) == -1) {
        fprintf(stderr, "Couldn't set promisc mode: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (pcap_activate(pcap_handle)) {
        fprintf(stderr, "Couldn't activate pcap: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    
    if (verbose)
        printf("Opening tunnel at %s with MAC %s\n", in_device, in_mac);
    
    snprintf(filter, PCAP_FILTER_LENGTH, "ether dst %s and ether src %s and pppoes", in_mac, out_mac);
    if (verbose)
        printf("Using BPF '%s'\n", filter);
    
    if (pcap_compile(pcap_handle, &pcap_filter, filter, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (pcap_setfilter(pcap_handle, &pcap_filter) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    
    pcap_fd = pcap_get_selectable_fd(pcap_handle);
    if (pcap_fd < 0) {
        fprintf(stderr, "Unable to get a selectable fd from pcap in_device\n");
        return 2;
    }

    dnet_handle = eth_open(out_device);
    if (dnet_handle == NULL) {
        fprintf(stderr, "Couldn't open out_device: %s\n", out_device);
        return 2;
    }
    if (verbose)
        printf("Sending to MAC %s on interface %s\n", out_mac, out_device);

    fm = max(tun_fd, pcap_fd) + 1;
    FD_ZERO(&fds);
    FD_SET(tun_fd, &fds);
    FD_SET(pcap_fd, &fds);

    for(run = 1; run; run++)
    {
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = TIMEOUT_USEC;

        ret = select(fm, &fds, NULL, NULL, &timeout);
        bzero(out, WRITE_BUFFER_SIZE);

        if (run % CHECK_FOR_LOCKFILE || !ret) {
            if(stat(lock_file, &fcheck))
                break;
            run = 1;
        }
        
        if( FD_ISSET(tun_fd, &fds) ) {      //IN on TUN
            len = l = read(tun_fd, in, READ_BUFFER_SIZE);
            start = out;

            eheader = (struct ether_header *) start;
            memcpy(eheader->ether_dhost, ETH_OCTET(ether_aton(out_mac)), ETH_ALEN);
            memcpy(eheader->ether_shost, ETH_OCTET(ether_aton(in_mac)), ETH_ALEN);
            eheader->ether_type = htons(0x8864);
            start += sizeof(struct ether_header);
            l += sizeof(struct ether_header);

            //add pppoe session header
            *start = 0x11; l += 1; start++; //version = 1, type = 1
            *start = 0x00; l += 1; start++; //code = session data
            *(uint16_t *) start = htons(session_id); l += 2; start +=2;
            *(uint16_t *) start = htons(len + 2); l += 2; start += 2; //plen = original len + ppp header
            
            //add ppp header
            *(uint16_t *) start = htons(0x0021); l += 2; start += 2; //protocol = ip

            memcpy(start, in, len);
            
            if (verbose) {
                printf("t");
                fflush(stdout);
            }
            if (eth_send(dnet_handle, (u_char *) in, l) < 0) {
                fprintf(stderr, "Couldn't write packet\n");
                return 2;
            }
        }
        if( FD_ISSET(pcap_fd, &fds) ) {      //IN on PCAP
            if(pcap_next_ex(pcap_handle, &pcap_header, &pcap_packet) > 0) {
                l = pcap_header->len;
                memcpy(in, pcap_packet, min(READ_BUFFER_SIZE, l));
                start = in;

                eheader = (struct ether_header *) start;
                start += sizeof(struct ether_header);
                
                //skip pppoe session header
                start += 6;
                l -= 6;
                
                if (ntohs(*(uint16_t *) start) != 0x0021) {
                    //were only interested in ip payload
                    
                    if (verbose) {
                        printf("i");
                        fflush(stdout);
                    }
                    continue;
                }
                //skip ppp header
                start += 2;
                l -= 2;
                
                
                if (verbose) {
                    printf("p");
                    fflush(stdout);
                }
                l = write(tun_fd, start, l);
            } else {
                fprintf(stderr, "Error on reading from pcap interface  %s\n", pcap_geterr(pcap_handle));
                return 2;
            }
        }
   }

   close(tun_fd);
   pcap_close(pcap_handle);
   eth_close(dnet_handle);
   
   return 0;
}
