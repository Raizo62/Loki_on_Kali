#       bf.pyx
#       
#       Copyright 2015 Daniel Mende <dmende@ernw.de>
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from libc.stdlib cimport malloc, free
from libc.string cimport memcpy

cdef extern from "Python.h":
    object PyString_FromStringAndSize(char *, Py_ssize_t)
    object PyString_FromString(char *)
    char *PyString_AsString(object)
    

cdef extern from "bf.h":
    ctypedef enum bf_error:
        BF_SUCCESS = 0
        BF_ERR_NO_MEM
        BF_ERR_PTHREAD
        BF_ERR_RUNNING
        BF_ERR_NOT_RUNNING
        BF_ERR_INVALID_ARGUMENT
        BF_ERR_NOT_FOUND
    ctypedef enum bf_mode:
        BF_WORDLIST
        BF_ALPHANUM
        BF_FULL
    ctypedef struct bf_state_t:
        pass
    bf_error bf_state_new(bf_state_t **)
    bf_error bf_state_delete(bf_state_t *)
    bf_error bf_set_wordlist(bf_state_t *, char *)
    bf_error bf_set_mode(bf_state_t *, bf_mode)
    bf_error bf_set_num_threads(bf_state_t *, unsigned)
    bf_error bf_set_pre_data(bf_state_t *, char *, unsigned)
    bf_error bf_set_hash_data(bf_state_t *, char *, unsigned)
    bf_error bf_get_wordlist(bf_state_t *, char **)
    bf_error bf_get_mode(bf_state_t *, bf_mode *)
    bf_error bf_get_num_threads(bf_state_t *, unsigned *)
    bf_error bf_get_pre_data(bf_state_t *, char **, unsigned *)
    bf_error bf_get_hash_data(bf_state_t *, char **, unsigned *)
    bf_error bf_start(bf_state_t *)
    bf_error bf_check_finished(bf_state_t *)
    bf_error bf_stop(bf_state_t *)
    bf_error bf_get_secret(bf_state_t *, char **)
    bf_error bf_get_current_secret(bf_state_t *, char **)

MODE_WORDLIST = BF_WORDLIST
MODE_ALPHANUM = BF_ALPHANUM
MODE_FULL = BF_FULL

ctypedef bf_error (*get_fun_t)(bf_state_t *, char **, unsigned *)
ctypedef bf_error (*set_fun_t)(bf_state_t *, char *, unsigned)

cdef class bf:
    cdef bf_state_t *state
    error_to_str = {    BF_SUCCESS      :           "SUCCESS",
                        BF_ERR_NO_MEM   :           "OUT_OF_MEMORY_ERROR",
                        BF_ERR_PTHREAD  :           "PTHREAD_ERROR",
                        BF_ERR_RUNNING  :           "IS_RUNNING_ERROR",
                        BF_ERR_RUNNING  :           "IS_NOT_RUNNING ERROR",
                        BF_ERR_INVALID_ARGUMENT :   "INVALID_ARGUMENT_ERROR",
                        BF_ERR_NOT_FOUND    :       "NOT_FOUND_ERROR",
                        }
    
    def __cinit__(self):
        cdef bf_error err
        err = bf_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
    
    def __dealloc__(self):
        cdef bf_error err
        cdef char *data
        cdef unsigned length
        err = bf_get_wordlist(self.state, <const char **>&data)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
        if not data is NULL:
            free(data)
        err = bf_get_pre_data(self.state, <const char **>&data, &length)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
        if not data is NULL:
            free(data)
        err = bf_get_hash_data(self.state, <const char **>&data, &length)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
        if not data is NULL:
            free(data)
        err = bf_state_delete(self.state)
        if err == BF_ERR_RUNNING:
            self.stop()
            err = bf_state_delete(self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
    
    cdef generic_set(self, get_fun_t get_fun, set_fun_t set_fun, str new_data):
        cdef bf_error err
        cdef char *data
        cdef unsigned length
        err = get_fun(self.state, &data, &length)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
        if length > 0 and not data is NULL:
            free(<void *>data)
        length = len(new_data)
        data = <char *>malloc(sizeof(char) * length)
        memcpy(<void *>data, PyString_AsString(new_data), length)
        err = set_fun(self.state, data, length)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
    
    cdef generic_get(self, get_fun_t get_fun):
        cdef bf_error err
        cdef char *data
        cdef unsigned length
        err = get_fun(self.state, &data, &length)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
        if data is NULL:
            return None
        else:
            return PyString_FromStringAndSize(data, <Py_ssize_t>length)

    property wordlist:
        def __set__(self, str new_data):
            cdef bf_error err
            cdef char *data
            length = len(new_data)
            err = bf_get_wordlist(self.state, <const char **>&data)
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
            if not data is NULL:
                free(<void *>data)
            data = <char *>malloc(sizeof(char) * (length + 1))
            memcpy(<void *>data, PyString_AsString(new_data), length)
            data[length] = '\0'
            err = bf_set_wordlist(self.state, data)
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
        def __get__(self):
            cdef bf_error err
            cdef char *wordlist
            err = bf_get_wordlist(self.state, <const char **>&wordlist)
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
            if wordlist is NULL:
                return ""
            else:
                return wordlist
    
    property mode:
        def __set__(self, bf_mode mode):
            cdef bf_error err
            err = bf_set_mode(self.state, mode)
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
        def __get__(self):
            cdef bf_error err
            cdef bf_mode mode
            err = bf_get_mode(self.state, &mode);
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
            return mode
    
    property num_threads:
        def __set__(self, int num):
            cdef bf_error err
            err = bf_set_num_threads(self.state, num)
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
        def __get__(self):
            cdef bf_error err
            cdef unsigned num_threads
            err = bf_get_num_threads(self.state, &num_threads)
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
            return num_threads

    property pre_data:
        def __set__(self, str new_data):
            self.generic_set(<get_fun_t>&bf_get_pre_data, <set_fun_t>&bf_set_pre_data, new_data)
        def __get__(self):
            self.generic_get(<get_fun_t>&bf_get_pre_data)
    
    property hash_data:
        def __set__(self, str new_data):
            self.generic_set(<get_fun_t>&bf_get_hash_data, <set_fun_t>&bf_set_hash_data, new_data)
        def __get__(self):
            self.generic_get(<get_fun_t>&bf_get_hash_data)
    
    property running:
        def __get__(self):
            cdef bf_error err
            err = bf_check_finished(self.state)
            if err > 0:
                return True
            return False

    property pw:
        def __get__(self):
            cdef bf_error err
            cdef char *data
            err = bf_get_secret(self.state, &data)
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
            if data is NULL:
                return None
            else:
                return PyString_FromString(data)

    property cur_pw:
        def __get__(self):
            cdef bf_error err
            cdef char *data
            err = bf_get_current_secret(self.state, &data)
            if err > 0:
                raise RuntimeError(self.error_to_str[err])
            if data is NULL:
                return None
            else:
                ret = PyString_FromString(data)
                free(data)
                return ret
    
    def start(self):
        cdef bf_error err
        err = bf_start(self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
    
    def stop(self):
        cdef bf_error err
        err = bf_stop(self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef extern from "bf/ospf.h":
    bf_error ospf_bf_md5_state_new(bf_state_t **)
    bf_error ospf_bf_hmac_sha1_state_new(bf_state_t **)
    bf_error ospf_bf_hmac_sha256_state_new(bf_state_t **)
    bf_error ospf_bf_hmac_sha384_state_new(bf_state_t **)
    bf_error ospf_bf_hmac_sha512_state_new(bf_state_t **)

cdef class ospf_md5_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = ospf_bf_md5_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef class ospf_hmac_sha1_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = ospf_bf_hmac_sha1_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef class ospf_hmac_sha256_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = ospf_bf_hmac_sha256_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef class ospf_hmac_sha384_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = ospf_bf_hmac_sha384_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef class ospf_hmac_sha512_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = ospf_bf_hmac_sha512_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef extern from "bf/isis.h":
    bf_error isis_bf_hmac_md5_state_new(bf_state_t **)
    bf_error isis_bf_hmac_sha1_state_new(bf_state_t **)
    bf_error isis_bf_hmac_sha256_state_new(bf_state_t **)

cdef class isis_hmac_md5_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = isis_bf_hmac_md5_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef class isis_hmac_sha1_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = isis_bf_hmac_sha1_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef class isis_hmac_sha256_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = isis_bf_hmac_sha256_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
        
cdef extern from "bf/tacacs.h":
    bf_error tacacs_bf_state_new(bf_state_t **)
    bf_error tacacs_bf_set_ciphertext(bf_state_t *, char *, unsigned)
    bf_error tacacs_bf_get_ciphertext(bf_state_t *, char **, unsigned *)

cdef class tacacs_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = tacacs_bf_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
    
    def __dealloc__(self):
        cdef bf_error err
        cdef char *data
        cdef unsigned length
        err = tacacs_bf_get_ciphertext(self.state, <const char **>&data, &length)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
        if not data is NULL:
            free(data)
    
    property ciphertext:
        def __set__(self, str new_data):
            self.generic_set(<get_fun_t>&tacacs_bf_get_ciphertext, <set_fun_t>&tacacs_bf_set_ciphertext, new_data)
        def __get__(self):
            self.generic_get(<get_fun_t>&tacacs_bf_get_ciphertext)
        
cdef extern from "bf/tcpmd5.h":
    bf_error tcpmd5_bf_state_new(bf_state_t **)

cdef class tcpmd5_bf(bf):
     def __cinit__(self):
        cdef bf_error err
        err = tcpmd5_bf_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef extern from "bf/bfd.h":
    bf_error bfd_bf_md5_state_new(bf_state_t **)
    bf_error bfd_bf_sha1_state_new(bf_state_t **)

cdef class bfd_md5_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = bfd_bf_md5_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])

cdef class bfd_sha1_bf(bf):
    def __cinit__(self):
        cdef bf_error err
        err = bfd_bf_sha1_state_new(&self.state)
        if err > 0:
            raise RuntimeError(self.error_to_str[err])
