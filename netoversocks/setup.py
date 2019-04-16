#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Copyright (c) CH, All rights reserved. Licensed by iduosi@icloud.com

import codecs
import os
from setuptools import setup


here = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with codecs.open(os.path.join(here, *parts), mode='r', encoding='utf-8') as fp:
        return fp.read()


with open('netoversocks/__init__.py') as f:
    ns = {}
    exec(f.read(), ns)
    version = ns["version"]


setup(
    name='netoversocks',
    version=version,
    license='http://www.apache.org/licenses/LICENSE-2.0',
    description="""A tunnel proxy that help you open a new world.""",
    author='iduosi',
    author_email='iduosi@icloud.com',
    maintainer='iduosi',
    maintainer_email='iduosi@icloud.com',
    url='https://github.com/catsaysuwasadog/netover',
    packages=['netoversocks', 'netoversocks.cryptographic'],
    package_data={'netoversocks': ['README.rst', 'LICENSE']},
    install_requires=[],
    entry_points="""
    [console_scripts]
    nonodecli = netoversocks.nodecli:main
    noserver = netoversocks.server:main
    """,
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=read('README.rst'),
)
