import binascii
import os
import time
from contextlib import contextmanager

import asyncssh
from asyncssh import MSG_KEXINIT
from asyncssh.kex import expand_kex_algs
from asyncssh.kex_dh import MSG_KEXDH_REPLY, MSG_KEX_ECDH_REPLY
# from asyncssh.kex_ecdh import MSG_KEX_ECDH_REPLY
from asyncssh.packet import NameList, Byte, Boolean, UInt32


def _send_kexinit(self, secret_mgmt):
    """Start a key exchange"""

    self._kex_complete = False
    self._rekey_bytes_sent = 0
    self._rekey_time = time.monotonic() + self._rekey_seconds

    gss_mechs = self._gss.mechs if self._gss else []
    kex_algs = expand_kex_algs(self._kex_algs, gss_mechs,
                               bool(self._server_host_key_algs))

    host_key_algs = self._server_host_key_algs or [b'null']

    self.logger.debug1('Requesting key exchange')
    self.logger.debug2('  Key exchange algs: %s', kex_algs)
    self.logger.debug2('  Host key algs: %s', host_key_algs)
    self.logger.debug2('  Encryption algs: %s', self._enc_algs)
    self.logger.debug2('  MAC algs: %s', self._mac_algs)
    self.logger.debug2('  Compression algs: %s', self._cmp_algs)

    cookie = os.urandom(16)
    secret_mgmt.cookie = binascii.hexlify(cookie).decode()
    kex_algs = NameList(kex_algs + self._get_ext_info_kex_alg())
    host_key_algs = NameList(host_key_algs)
    enc_algs = NameList(self._enc_algs)
    mac_algs = NameList(self._mac_algs)
    cmp_algs = NameList(self._cmp_algs)
    langs = NameList([])

    packet = b''.join((Byte(MSG_KEXINIT), cookie, kex_algs, host_key_algs,
                       enc_algs, enc_algs, mac_algs, mac_algs, cmp_algs,
                       cmp_algs, langs, langs, Boolean(False), UInt32(0)))

    if self.is_server():
        self._server_kexinit = packet
    else:
        self._client_kexinit = packet

    self.send_packet(MSG_KEXINIT, packet[1:])


class SecretMgmt:

    def __init__(self, file_path):
        self.file_path = file_path
        self.file = None
        self.cookie = None
        self.__k = None

    def __enter__(self):
        self.file = open(self.file_path, "w")

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.close()
        self.file = None

    @property
    def k(self):
        return self.__k

    @k.setter
    def k(self, k):
        self.__k = k
        if self.file:
            self.file.write(f"{self.cookie} {self.k}{os.linesep}")
            self.file.flush()

    def _process_reply_dh(self, instance, _pkttype, _pktid, packet):
        instance._process_reply(_pkttype, _pktid, packet)
        k = instance._compute_client_shared()

        self.k = hex(k)[2:]

    def _process_reply_ecdh(self, instance, _pkttype, _pktid, packet):
        instance._process_reply(_pkttype, _pktid, packet)
        k = instance._priv.get_shared(instance._server_pub)

        self.k = hex(k)[2:]


@contextmanager
def async_secret(file_path='ssh.log'):
    secret_mgmt = SecretMgmt(file_path)

    _send_kexinit_orig = asyncssh.connection.SSHConnection._send_kexinit
    process_reply_orig = asyncssh.kex_dh._KexDH._packet_handlers[MSG_KEXDH_REPLY]
    # process_reply_ecdh_orig = asyncssh.kex_ecdh._KexECDH._packet_handlers[MSG_KEX_ECDH_REPLY]
    process_reply_ecdh_orig = asyncssh.kex_dh._KexECDH._packet_handlers[MSG_KEX_ECDH_REPLY]

    asyncssh.connection.SSHConnection._send_kexinit = lambda self: _send_kexinit(self, secret_mgmt)
    asyncssh.kex_dh._KexDH._packet_handlers[MSG_KEXDH_REPLY] = secret_mgmt._process_reply_dh
    # asyncssh.kex_ecdh._KexECDH._packet_handlers[MSG_KEX_ECDH_REPLY] = secret_mgmt._process_reply_ecdh
    asyncssh.kex_dh._KexECDH._packet_handlers[MSG_KEX_ECDH_REPLY] = secret_mgmt._process_reply_ecdh

    with secret_mgmt:
        yield

    asyncssh.connection.SSHConnection._send_kexinit = _send_kexinit_orig
    asyncssh.kex_dh._KexDH._packet_handlers[MSG_KEXDH_REPLY] = process_reply_orig
    # asyncssh.kex_ecdh._KexECDH._packet_handlers[MSG_KEX_ECDH_REPLY] = process_reply_ecdh_orig
    asyncssh.kex_dh._KexECDH._packet_handlers[MSG_KEX_ECDH_REPLY] = process_reply_ecdh_orig


