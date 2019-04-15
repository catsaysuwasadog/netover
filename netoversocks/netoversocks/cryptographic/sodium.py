#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Copyright (c) CH, All rights reserved. Licensed by iduosi@icloud.com

from __future__ import absolute_import, division, print_function, unicode_literals

from ctypes import c_char_p, c_int, c_ulonglong, byref, c_ulong, create_string_buffer, c_void_p
from netoversocks.cryptographic import util


__all__ = ['ciphers']

libsodium = None
loaded = False
buf_size = 2048
# for salsa20 and chacha20 and chacha20-ietf
BLOCK_SIZE = 64


def load_libsodium():
    global loaded, libsodium, buf

    libsodium = util.find_library('sodium', 'crypto_stream_salsa20_xor_ic', 'libsodium')

    if libsodium is None:
        raise Exception('libsodium not found')

    libsodium.crypto_stream_salsa20_xor_ic.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.argtypes = (c_void_p, c_char_p, c_ulonglong, c_char_p, c_ulonglong, c_char_p)
    libsodium.crypto_stream_chacha20_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_xor_ic.argtypes = (c_void_p, c_char_p, c_ulonglong, c_char_p, c_ulonglong, c_char_p)
    libsodium.crypto_stream_chacha20_ietf_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_ietf_xor_ic.argtypes = (c_void_p, c_char_p, c_ulonglong, c_char_p, c_ulong, c_char_p)

    buf = create_string_buffer(buf_size)
    loaded = True


class SodiumCrypto(object):
    def __init__(self, cipher_name, key, iv, op):
        if not loaded:
            load_libsodium()

        self.key = key
        self.iv = iv
        self.key_ptr = c_char_p(key)
        self.iv_ptr = c_char_p(iv)

        if cipher_name == 'salsa20':
            self.cipher = libsodium.crypto_stream_salsa20_xor_ic
        elif cipher_name == 'chacha20':
            self.cipher = libsodium.crypto_stream_chacha20_xor_ic
        elif cipher_name == 'chacha20-ietf':
            self.cipher = libsodium.crypto_stream_chacha20_ietf_xor_ic
        else:
            raise Exception('Unknown cipher')

        # byte counter, not block counter
        self.counter = 0

    def update(self, data):
        global buf_size, buf

        l = len(data)
        # we can only prepend some padding to make the encryption align to blocks
        padding = self.counter % BLOCK_SIZE

        if buf_size < padding + l:
            buf_size = (padding + l) * 2
            buf = create_string_buffer(buf_size)

        if padding:
            data = (b'\0' * padding) + data

        self.cipher(byref(buf), c_char_p(data), padding + l, self.iv_ptr, int(self.counter / BLOCK_SIZE), self.key_ptr)
        self.counter += l
        # buf is copied to a str object when we access buf.raw strip off the padding
        return buf.raw[padding:padding + l]


ciphers = {
    'salsa20': (32, 8, SodiumCrypto),
    'chacha20': (32, 8, SodiumCrypto),
    'chacha20-ietf': (32, 12, SodiumCrypto),
}
