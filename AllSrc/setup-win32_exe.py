from cx_Freeze import setup, Executable
import glob
import sys
import os

sys.path.append('./src')

options = {
  'build_exe': {
    'includes': [ 'gtk.keysyms', 'dumbdbm', 'dbhash', 'new', 'numbers',
                  'hashlib', 'gtk.glade', 'hmac', 'IPy', 'dnet', 'loki' ],
    'base': 'Console',
#    'base': 'Win32GUI',
    'include_files': [ 'modules' ]
    }
  }

setup(
  name='Loki',
  version='0.3.0',
  description='Loki',
  author='Daniel Mende',
  url='http://codecafe.de/loki.html',
  license='GPL',
  options=options,
  executables=[ Executable('src/loki_gtk.py'),
#                Executable('src/loki_urw.py'),
                ],
) 

#os.system("mt.exe -manifest pkg_scripts\\loki.exe.manifest -outputresource:\"build\\exe.win32-2.6\\loki_gtk.exe;#1\"")
#os.system("mt.exe -manifest pkg_scripts\\loki.exe.manifest -outputresource:\"build\\exe.win32-2.6\\loki_urw.exe;#1\"")
