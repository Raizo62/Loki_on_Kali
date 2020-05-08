/*
 *      mplsred.c
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

#include <mplsred.h>

int mplsred(char *in_device, char *out_device, int num_label, uint16_t in_label, uint16_t out_label, char *filter, char *lock_file, int verbose)
{
    int run, ret;
    int len;
    int cur_label;
    struct stat fcheck;
    
    unsigned label;
    u_char local_packet[MAX_PACKET_LEN];

    int pcap_fd,fm;
    fd_set fds;
    struct timeval timeout;
    
    pcap_t *pcap_handle;
    const u_char *pcap_packet;
    struct pcap_pkthdr *pcap_header;
    struct bpf_program pcap_filter;

    eth_t *libdnet_handle;
    
    pcap_handle = pcap_create(in_device, NULL);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (pcap_set_promisc(pcap_handle, 1) == -1) {
        fprintf(stderr, "Couldn't set promisc mode: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (pcap_set_timeout(pcap_handle, TIMEOUT_SEC * 1000 + TIMEOUT_USEC)) {
        fprintf(stderr, "Couldn't set read timeout: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (pcap_activate(pcap_handle)) {
        fprintf(stderr, "Couldn't activate pcap: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (verbose)
        printf("Capturing on device %s\n", in_device);
        
    if (pcap_compile(pcap_handle, &pcap_filter, filter, 1, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (pcap_setfilter(pcap_handle, &pcap_filter) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (verbose)
        printf("Using filter %s\n", filter);

    pcap_fd = pcap_get_selectable_fd(pcap_handle);
    if (pcap_fd < 0) {
        fprintf(stderr, "Unable to get a selectable fd from pcap in_device\n");
        return 2;
    }

	libdnet_handle = eth_open(out_device);
    if (libdnet_handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", out_device);
        return 2;
    }
    if (verbose)
        printf("Injecting on device %s\n", out_device);
    if (verbose)
        printf("Redirecting from MPLS label %i to MPLS label %i\n", in_label, out_label);

    fm = pcap_fd + 1;
    FD_ZERO(&fds);
    FD_SET(pcap_fd, &fds);

    for(run = 1; run; run++)
    {
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = TIMEOUT_USEC;
        ret = select(fm, &fds, NULL, NULL, &timeout);
        
        if (run % CHECK_FOR_LOCKFILE || !ret) {
            if(verbose)
                printf("checking for lockfile\n");
            if(stat(lock_file, &fcheck))
                break;
            run = 1;
        }
        
        //if( FD_ISSET(pcap_fd, &fds) ) {
            if(pcap_next_ex(pcap_handle, &pcap_header, &pcap_packet) > 0) {
                len = pcap_header->len > MAX_PACKET_LEN ? MAX_PACKET_LEN : pcap_header->len;
                if (pcap_packet[12] != 0x88 || pcap_packet[13] != 0x47)
                    continue;
                memcpy(local_packet, pcap_packet, len);

                for (cur_label = 0; cur_label < num_label && cur_label >= 0; ++cur_label)
                    if (*((unsigned *) (local_packet + 14 + cur_label * 4)) & htonl(0x00000100))
                        cur_label = -1;
                if (cur_label == -1) {
                    if (verbose)
                        printf("#");
                    continue;
                }
                label = ntohl(*((unsigned *) (local_packet + 14 + cur_label * 4)) & htonl(0xfffff000)) >> 12;
                if (label != in_label) {
                    if (verbose)
                        printf(".");
                    continue;
                }
                if (verbose)
                    printf("*");
                *((unsigned *) (local_packet + 14 + cur_label * 4)) &= htonl(0x00000fff);
                *((unsigned *) (local_packet + 14 + cur_label * 4)) |= htonl(out_label << 12);

                if (eth_send(libdnet_handle, local_packet, len) < 0) {
                    fprintf(stderr, "Couldn't write packet\n");
                    return 2;
                }
            }
        //}
    }

    pcap_close(pcap_handle);
    eth_close(libdnet_handle);

    return 0;
}
