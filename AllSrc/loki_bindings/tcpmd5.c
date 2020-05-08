/*
 *      tcpmd5.c
 *
 *      Copyright 2009 Daniel Mende <dmende@ernw.de>
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

#include <Python.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/tcp.h>

#ifdef __FreeBSD__
#include <stdio.h>
#include <stdlib.h>
#endif

static PyObject *
tcpmd5_set(PyObject *self, PyObject *args) {
    int sock, port, pw_len;
    const char *pw, *src, *dst;
#ifdef linux
    struct tcp_md5sig md5args;
    struct sockaddr_in sin;
#endif

#ifdef __FreeBSD__
    int one = 1;
    char cmd[1024];
#endif    

    if(!PyArg_ParseTuple(args, "issis#", &sock, &src, &dst, &port, &pw, &pw_len))
        return NULL;

#ifdef linux    
    memset(&sin, 0, sizeof(sin));
    sin.sin_port = port;
    if(!inet_aton(dst, &sin.sin_addr)) {
        printf("Can't convert %s to in_addr\n", dst);
        return NULL;
    }
    sin.sin_family = AF_INET;

    memset(&md5args, 0, sizeof(md5args));
    memcpy(&md5args.tcpm_addr, &sin, sizeof(sin));
    md5args.tcpm_keylen = strlen(pw);
    memcpy(md5args.tcpm_key, pw, TCP_MD5SIG_MAXKEYLEN);
    if(setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &md5args, sizeof(md5args)))
        printf("Enable TCP MD5 signing failed: %s\n", strerror(errno));
#endif

#ifdef __FreeBSD__
    if(setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &one, sizeof(one)))
        printf("Enable TCP MD5 signing failed: %s\n", strerror(errno));
    snprintf(cmd, 1024, "setkey -c << EOF\nadd -4 %s %s tcp 0x1000 -A tcp-md5 \"%s\" ;\nEOF\n", src, dst, pw);
    system(cmd);
#endif

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
tcpmd5_clear(PyObject *self, PyObject *args) {
    int sock, port;
    const char *src, *dst;
#ifdef linux
    struct tcp_md5sig md5args;
    struct sockaddr_in sin;
#endif

#ifdef __FreeBSD__
    int zero = 0;
    char cmd[1024];
#endif    

    if(!PyArg_ParseTuple(args, "issi", &sock, &src, &dst, &port))
        return NULL;

#ifdef linux    
    memset(&sin, 0, sizeof(sin));
    sin.sin_port = port;
    if(!inet_aton(dst, &sin.sin_addr)) {
        printf("Can't convert %s to in_addr\n", dst);
        return NULL;
    }
    sin.sin_family = AF_INET;

    memset(&md5args, 0, sizeof(md5args));
    memcpy(&md5args.tcpm_addr, &sin, sizeof(sin));
    md5args.tcpm_keylen = 0;
    memcpy(md5args.tcpm_key, "", TCP_MD5SIG_MAXKEYLEN);
    if(setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &md5args, sizeof(md5args)))
        printf("Enable TCP MD5 signing failed: %s\n", strerror(errno));
#endif

#ifdef __FreeBSD__
    if(setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &zero, sizeof(zero)))
        printf("Enable TCP MD5 signing failed: %s\n", strerror(errno));
    snprintf(cmd, 1024, "setkey -c << EOF\ndelete -4 %s %s tcp 0x1000 ;\nEOF\n", src, dst);
    system(cmd);
#endif

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef Tcpmd5Methods[] = {
    {"set",  tcpmd5_set, METH_VARARGS, "Sets tcp md5 signing options"},
    {"clear", tcpmd5_clear, METH_VARARGS, "Clears tcp md5 signing options"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
inittcpmd5(void)
{
    PyObject *m;

    m = Py_InitModule("tcpmd5", Tcpmd5Methods);
    if (m == NULL)
        return;
}
