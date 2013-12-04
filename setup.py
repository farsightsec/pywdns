#!/usr/bin/env python

NAME = 'pywdns'
VERSION = '0.5'

from distutils.core import setup
from distutils.extension import Extension
import os

os.system('./gen_pywdns_constants')

try:
    from Cython.Distutils import build_ext
    setup(
        name = NAME,
        version = VERSION,
        ext_modules = [ Extension('wdns', ['wdns.pyx'], libraries = ['wdns']) ],
        cmdclass = {'build_ext': build_ext},
        py_modules = ['wdns_constants'],

    )
except ImportError:
    if os.path.isfile('wdns.c'):
        setup(
            name = NAME,
            version = VERSION,
            ext_modules = [ Extension('wdns', ['wdns.c'], libraries = ['wdns']) ],
            py_modules = ['wdns_constants'],
        )
    else:
        raise
