#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Copyright (c) CH, All rights reserved. Licensed by iduosi@icloud.com

from __future__ import absolute_import, division, print_function

import hashlib
from netoversocks.cryptographic import openssl

__all__ = ['ciphers']


def create_cipher(alg, key, iv, op, key_as_bytes=0, d=None, salt=None, i=1, padding=1):
    md5 = hashlib.md5()
    md5.update(key)
    md5.update(iv)
    rc4_key = md5.digest()

    return openssl.OpenSSLCrypto(b'rc4', rc4_key, b'', op)


ciphers = {'rc4-md5': (16, 16, create_cipher), }
