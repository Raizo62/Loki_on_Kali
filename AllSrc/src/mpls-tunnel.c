/*
 *      mpls-tunnel.c
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
 
#include <libgen.h>
#include <mplstun.h>

#define LOCKFILE_LENGTH 256
char lockfile[LOCKFILE_LENGTH];

void sigint(int sig) {
    remove(lockfile);
}

void usage(char *name) {
    fprintf(stderr, "Usage: %s [-v] -m mode -d in_device -D out_device -i in_label -o out_label -I in_mac -O out_mac [-t in_trans] [-T out_trans]\n\n", name);
    fprintf(stderr, "-v\t\t: Be verbose\n");
    fprintf(stderr, "-m\t\t: Mode: l3vpn l2vpn\n");
    fprintf(stderr, "-d in_device\t: in_device for tunnel data\n");
    fprintf(stderr, "-D out_device\t: out_device for tunnel data\n");
    fprintf(stderr, "-i in_label\t: Label of incomming traffic\n");
    fprintf(stderr, "-o out_label\t: Label of outgoing traffic\n");
    fprintf(stderr, "-I in_mac\t: Incomming MAC address\n");
    fprintf(stderr, "-O out_mac\t: Outgoing MAC address\n");
    fprintf(stderr, "-t in_label\t: Transport label of incomming traffic\n");
    fprintf(stderr, "-T out_label\t: Transport label of outgoing traffic\n\n");
}

int main(int argc, char *argv[])
{
    int opt;

    char nullstr[2] = "0\n";
    int verbose = 0;
    char *mode = NULL;
    char *in_device = NULL;
    char *out_device = NULL;
    char *in_label = NULL;
    char *out_label = NULL;
    char *in_mac = NULL;
    char *out_mac = NULL;
    char *in_trans = nullstr;
    char *out_trans = nullstr;
    tun_mode tmode = NONE_TUN;

    int pid;
    char *name;
    FILE *lfile;

    printf("%s version %s\t\tby Daniel Mende - dmende@ernw.de\n", argv[0], VERSION);
    fflush(stdout);
    
    while ((opt = getopt(argc, argv, "vm:d:D:i:o:I:O:ht:T:")) != -1) {
        switch (opt) {
        case 'v':
            verbose = 1;
            break;
        case 'm':
            mode = optarg;
            break;
        case 'd':
            in_device = optarg;
            break;
        case 'D':
            out_device = optarg;
            break;
        case 'i':
            in_label = optarg;
            break;
        case 'o':
            out_label = optarg;
            break;
        case 'I':
            in_mac = optarg;
            break;
        case 'O':
            out_mac = optarg;
            break;
        case 't':
            in_trans = optarg;
            break;
        case 'T':
            out_trans = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return 2;
        }
    }

    if(!mode) {
        usage(argv[0]);
        return 2;
    }
    if(!(strcmp(mode, "l3vpn") || strcmp(mode, "l2vpn"))) {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        return 2;
    }
    if(!in_mac) {
        fprintf(stderr, "No incoming MAC given\n");
        return 2;
    }
    if(!out_mac) {
        fprintf(stderr, "No outgoing MAC given\n");
        return 2;
    }
    if(!in_device) {
        fprintf(stderr, "No in_device for capturing given\n");
        return 2;
    }
    if(!out_device) {
        fprintf(stderr, "No out_device for injection given\n");
        return 2;
    }
    if(!in_label) {
        fprintf(stderr, "No incomming label given\n");
        return 2;
    }
    if(!out_label) {
        fprintf(stderr, "No outgoing label given\n");
        return 2;
    }

    signal(SIGINT, sigint);

    if (!strcmp(mode, "l3vpn")) {
        tmode = L3_TUN;
    } else {
        tmode = L2_TUN;
    }

    pid = getpid();
    name = strdup(argv[0]);
    snprintf(lockfile, LOCKFILE_LENGTH, "/tmp/%s-%d-lock", basename(name), pid);
    lfile = fopen(lockfile, "w+");
    if(lfile == NULL) {
        fprintf(stderr, "Couldn't open lockfile '%s': %s\n", lockfile, strerror(errno));
        return 2;
    }
    fclose(lfile);
    free(name);
    
    mplstun_v(tmode, in_device, out_device, atoi(in_label), atoi(out_label), in_mac, out_mac, atoi(in_trans), atoi(out_trans), lockfile, verbose);
   
   return 0;
}
