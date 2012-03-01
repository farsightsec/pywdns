#!/usr/bin/env python

from distutils.core import setup
from distutils.extension import Extension

try:
    from Cython.Distutils import build_ext
    setup(
        name = 'wdns',
        ext_modules = [ Extension('wdns', ['wdns.pyx'], libraries = ['wdns']) ],
        cmdclass = {'build_ext': build_ext},
        py_modules = ['wdns_constants'],

    )
except ImportError:
    setup(
        name = 'wdns',
        ext_modules = [ Extension('wdns', ['wdns.c'], libraries = ['wdns']) ],
        py_modules = ['wdns_constants'],
    )
