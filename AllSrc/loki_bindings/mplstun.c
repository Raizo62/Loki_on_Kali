/*
 *      mplstun.c
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

#include <Python.h>

#include <string.h>

#include <mplstun.h>

static PyObject *
mpls_tun(PyObject *self, PyObject *args)
{
    tun_mode mode;
    char *mode_str;
    char *in_device, *out_device;
    uint16_t in_label, out_label;
    char *in_mac, *out_mac;
    uint16_t in_trans_label, out_trans_label;
    char *lock_file;
    
    if(!PyArg_ParseTuple(args, "sssiissiis", &mode_str, &in_device, &out_device, &in_label, &out_label, &in_mac, &out_mac, &in_trans_label, &out_trans_label, &lock_file))
        return NULL;

    if(!strcmp(mode_str, "l2_tun"))
        mode = L2_TUN;
    else if(!strcmp(mode_str, "l3_tun"))
        mode = L3_TUN;
    else
        mode = NONE_TUN;

    Py_BEGIN_ALLOW_THREADS
    mplstun(mode, in_device, out_device, in_label, out_label, in_mac, out_mac, in_trans_label,  out_trans_label, lock_file);
    Py_END_ALLOW_THREADS

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef MplstunMethods[] = {
    {"mplstun", mpls_tun, METH_VARARGS, "Opens an MPLS capable tunnel device"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initmplstun(void)
{
    PyObject *m;

    m = Py_InitModule("mplstun", MplstunMethods);
    if (m == NULL)
        return;
}
