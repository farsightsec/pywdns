# Copyright (c) 2009-2015, 2017, 2019-2020 by Farsight Security, Inc.
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

from Cython.Distutils import build_ext
from distutils.core import setup, Command
from distutils.extension import Extension
import subprocess
import unittest


NAME = 'pywdns'
VERSION = '0.10.0'
LICENSE = 'Apache License 2.0'
DESCRIPTION = 'Python extension module for the wdns C library'
URL = 'https://github.com/farsightsec/pywdns'
AUTHOR = 'Farsight Security, Inc.'
AUTHOR_EMAIL = 'software@farsightsecurity.com'


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
    pkg_config_output = subprocess.check_output(
        pkg_config_cmd, universal_newlines=True)
    for token in pkg_config_output.split():
        flag = token[:2]
        arg = token[2:]
        if flag in flag_map:
            kw.setdefault(flag_map[flag], []).append(arg)
    return kw


class Test(Command):

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        unittest.TextTestRunner(verbosity=1).run(
            unittest.TestLoader().discover('tests'))


setup(
    name=NAME,
    version=VERSION,
    license=LICENSE,
    description=DESCRIPTION,
    url=URL,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    ext_modules=[
        Extension('wdns', ['wdns.pyx'],
                  **pkgconfig('libwdns >= 0.9.0'))
    ],
    cmdclass={'build_ext': build_ext, 'test': Test},
    py_modules=['wdns_constants'],
)
