/*
 *      asleap.c
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

#include <stdio.h>
#include <string.h>

#include "lib/asleap/asleap.h"
#include "lib/asleap/sha1.h"

extern int attack_leap(struct asleap_data *asleap);

static PyObject *
atk_leap(PyObject *self, PyObject *args)
{
    struct asleap_data data;
    int chall_len, resp_len, id, user_len;
    char *wl, *challenge, *response, *user;

    if(!PyArg_ParseTuple(args, "ss#s#is#", &wl, &challenge, &chall_len, &response, &resp_len, &id, &user, &user_len))
        return NULL;
    
    bzero(&data, sizeof(struct asleap_data));
    if(chall_len != 8) {
        fprintf(stderr, "Challange len != 8\n");
        Py_INCREF(Py_None);
        return Py_None;
    }
    memcpy(data.challenge, challenge, 8);

    if(resp_len != 24) {
        fprintf(stderr, "Response len != 24\n");
        Py_INCREF(Py_None);
        return Py_None;
    }
    memcpy(data.response, response, 24);
    data.eapid = id;

    if(!user_len || user_len > 256)  {
        fprintf(stderr, "Username len invalid\n");
        Py_INCREF(Py_None);
        return Py_None;
    }
    strncpy(data.username, user, 256);

    data.verbose = 0;
    strncpy(data.wordfile, wl, 255);

    data.leapchalfound = 1;
	data.leaprespfound = 1;
    data.manualchalresp = 1;

    attack_leap(&data);

    return Py_BuildValue("s", data.password);
}

static PyMethodDef AsleapMethods[] = {
    {"attack_leap", atk_leap, METH_VARARGS, "Bruteforce cracking of asleap"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initasleap(void)
{
    PyObject *m;

    m = Py_InitModule("asleap", AsleapMethods);
    if (m == NULL)
        return;
}
