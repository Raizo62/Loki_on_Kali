# setup.py.in
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

import os
from distutils.core import setup, Extension
from Cython.Build import cythonize

#~ mplsred_srcs = [ 'loki_bindings/mpls/mplsred.c', 'lib/mplsred.c' ]
#~ mplsred_incdirs = [ '.', 'C:\\Users\\greif\\Downloads\\libdnet-1.12\\libdnet-1.12\\include' ]
#~ mplsred_libs = ['wpcap', 'dnet', 'ws2_32', 'packet', 'iphlpapi']
#~ mplsred_libdirs = [ 'C:\\Users\\greif\\Downloads\\libdnet-1.11-win32\\libdnet-1.11-win32\\lib',
                     #~ 'C:\\Users\\greif\\Downloads\\libdnet-1.12\\WpdPack\\Lib' ]
#~ mplsred_extargs = []
#~ mplsred_extobj = []

bf_srcs = [ './loki_bindings/bf.pyx', 
            './lib/bf.c',
            './lib/bf/ospf.c',
            './lib/bf/isis.c',
            './lib/bf/tacacs.c',
            './lib/bf/tcpmd5.c',
            './lib/bf/bfd.c',
            './lib/algos/md5.c',
            './lib/algos/hmac_md5.c',
            './lib/algos/sha1.c',
            './lib/algos/sha2.c',
            './lib/algos/hmac_sha2.c', ]
bf_incdirs = [ './include', os.environ['win32-pthread_inc'] ]
bf_libdirs = [ os.environ['win32-pthread_lib'] ]
bf_libs = [ 'ws2_32', 'pthreadVC2' ]

#~ mplsred = Extension(    'loki_bindings.mpls.mplsred',
                        #~ mplsred_srcs,
                        #~ include_dirs=mplsred_incdirs,
                        #~ libraries=mplsred_libs,
                        #~ library_dirs=mplsred_libdirs,
                        #~ extra_compile_args=mplsred_extargs,
                        #~ extra_objects=mplsred_extobj)

bf = Extension( 'loki_bindings.bf',
                bf_srcs,
                include_dirs=bf_incdirs,
                library_dirs=bf_libdirs,
                libraries=bf_libs )

setup(name='loki_bindings',
      version='0.3.0',
      description='',
      author='Daniel Mende',
      author_email='dmende@ernw.de',
      url='https://c0decafe.de',
      packages=['loki_bindings'],
      ext_modules=cythonize(bf)
     )
