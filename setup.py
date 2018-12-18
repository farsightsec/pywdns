#!/usr/bin/env python

# Copyright (c) 2009-2014 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

NAME = 'pywdns'
VERSION = '0.6.0'

from distutils.core import setup
from distutils.extension import Extension
import subprocess

subprocess.check_call('./gen_pywdns_constants')

def pkgconfig(*packages, **kw):
    flag_map = {
            '-I': 'include_dirs',
            '-L': 'library_dirs',
            '-l': 'libraries'
    }
    pkg_config_cmd = (
        'pkg-config',
        '--cflags',
        '--libs',
        ' '.join(packages),
    )
    pkg_config_output = subprocess.check_output(pkg_config_cmd, universal_newlines=True)
    for token in pkg_config_output.split():
        flag = token[:2]
        arg = token[2:]
        if flag in flag_map:
            kw.setdefault(flag_map[flag], []).append(arg)
    return kw

try:
    from Cython.Distutils import build_ext
    setup(
        name = NAME,
        version = VERSION,
        ext_modules = [ Extension('wdns', ['wdns.pyx'], **pkgconfig('libwdns >= 0.6.0')) ],
        cmdclass = {'build_ext': build_ext},
        py_modules = ['wdns_constants'],

    )
except ImportError:
    import os
    if os.path.isfile('wdns.c'):
        setup(
            name = NAME,
            version = VERSION,
            ext_modules = [ Extension('wdns', ['wdns.c'], **pkgconfig('libwdns >= 0.6.0')) ],
            py_modules = ['wdns_constants'],
        )
    else:
        raise
