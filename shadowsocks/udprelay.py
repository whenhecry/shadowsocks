#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+

# HOW TO NAME THINGS
# ------------------
# `dest`    means destination server, which is from DST fields in the SOCKS5
#           request
# `local`   means local server of shadowsocks
# `remote`  means remote server of shadowsocks
# `client`  means UDP clients that connects to other servers
# `server`  means the UDP server that handles user requests

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket
import logging
import struct
import errno
import random

from shadowsocks import encrypt, eventloop, lru_cache, common, shell
from shadowsocks.common import parse_header, pack_addr


BUF_SIZE = 65536


def client_key(source_addr, server_af):
    # notice this is server af, not dest af
    return '%s:%s:%d' % (source_addr[0], source_addr[1], server_af)


# relay server is either local or remote
class UDPRelay(object):
    def __init__(self, config, dns_resolver, is_local, stat_callback=None):
        self._config = config

        # analyse config
        if is_local:
            self._listen_addr = config['local_address']
            self._listen_port = config['local_port']
            self._remote_addr = config['server']
            self._remote_port = config['server_port']
        else:
            self._listen_addr = config['server']
            self._listen_port = config['server_port']
            self._remote_addr = None
            self._remote_port = None
        self._dns_resolver = dns_resolver
        self._password = common.to_bytes(config['password'])
        self._method = config['method']
        self._timeout = config['timeout']
        self._is_local = is_local
        self._cache = lru_cache.LRUCache(timeout=config['timeout'],
                                         close_callback=self._close_client)
        self._client_fd_to_server_addr = \
            lru_cache.LRUCache(timeout=config['timeout'])
        self._dns_cache = lru_cache.LRUCache(timeout=300)
        self._eventloop = None
        self._closed = False
        self._sockets = set()
        if 'forbidden_ip' in config:
            self._forbidden_iplist = config['forbidden_ip']
        else:
            self._forbidden_iplist = None

        # init self._server_socket, namely the relay server socket
        # the server is either local or remote, due to self._listen_addr
        # then bind the socket to _listen_port
        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
        self._server_socket = server_socket
        self._stat_callback = stat_callback

    # get addr of remote server from config
    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if type(server_port) == list:
            server_port = random.choice(server_port)
        if type(server) == list:
            server = random.choice(server)
        logging.debug('chosen server: %s:%d', server, server_port)
        return server, server_port

    def _close_client(self, client):
        if hasattr(client, 'close'):
            self._sockets.remove(client.fileno())
            self._eventloop.remove(client)
            client.close()
        else:
            # just an address
            pass

    # rfc1928
    # 7.  Procedure for UDP-based clients
    # Each UDP datagram carries a UDP request header with it
    # header means all before DATA
    # +----+------+------+----------+----------+----------+
    # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    # +----+------+------+----------+----------+----------+
    # | 2  |  1   |  1   | Variable |    2     | Variable |
    # +----+------+------+----------+----------+----------+
    #
    # When a UDP relay server receives a reply datagram from a remote host, it
    # MUST encapsulate that datagram using the above UDP request header,
    # and any authentication-method-dependent encapsulation.

    # for a server to relay udp request
    def _handle_server(self):
        server = self._server_socket

        # receive request
        # note that no listen()/accept() is used as TCP
        # this is because udp doesn't require long-lived connection
        # so the server does not need to listen for and accept connections
        # It only needs to use bind() to associate its socket with a port
        # and then wait for individual messages
        # _server_socket has been bound in __init__()
        data, r_addr = server.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_server: data is empty')
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))

        # for a local server, request is from local client
        # if the datagram isnot standalone, drop it
        if self._is_local:

            frag = common.ord(data[2])
            # FRAG    Current fragment number
            # ord() converts it back to number
            # The FRAG field indicates whether or not this datagram is one of a number of fragments.
            # Implementation of fragmentation is optional; an implementation that
            # does not support fragmentation MUST drop any datagram whose FRAG field is other than X'00'.

            if frag != 0:
                logging.warn('drop a message since frag is not 0')
                return
            else:
                data = data[3:]

        # for a remote server, request is from local server
        # decrypt it
        # note that no removal of first 3 bytes canbe found here, guess in decryption?
        else:
            data = encrypt.encrypt_all(self._password, self._method, 0, data)
            # decrypt data
            if not data:
                logging.debug('UDP handle_server: data is empty after decrypt')
                return

        # for both local and remote server, analyse request header
        header_result = parse_header(data)
        if header_result is None:
            return
        addrtype, dest_addr, dest_port, header_length = header_result

        # set a place where a server relays request to
        # a local server relays request to remote server
        if self._is_local:
            server_addr, server_port = self._get_a_server()
        # a remote server relays request to dest, extracted from request header
        else:
            server_addr, server_port = dest_addr, dest_port

        # try to find send-socket from cache
        addrs = self._dns_cache.get(server_addr, None)
        if addrs is None:
            addrs = socket.getaddrinfo(server_addr, server_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
            if not addrs:
                # drop
                return
            else:
                self._dns_cache[server_addr] = addrs
        af, socktype, proto, canonname, sa = addrs[0]
        key = client_key(r_addr, af)
        client = self._cache.get(key, None)

        # if not found in the cache, init a new send-socket
        # add it to the eventloop
        if not client:
            # TODO async getaddrinfo
            if self._forbidden_iplist:
                if common.to_str(sa[0]) in self._forbidden_iplist:
                    logging.debug('IP %s is in forbidden list, drop' %
                                  common.to_str(sa[0]))
                    # drop
                    return
            client = socket.socket(af, socktype, proto)
            client.setblocking(False)
            self._cache[key] = client
            self._client_fd_to_server_addr[client.fileno()] = r_addr

            self._sockets.add(client.fileno())
            self._eventloop.add(client, eventloop.POLL_IN, self)

        # process the request before relay
        # a local server relays request to remote server
        # so request should be encrypted
        if self._is_local:
            data = encrypt.encrypt_all(self._password, self._method, 1, data)
            if not data:
                return
        # a remote server relays request to dest
        # note that request has been decrypted before
        # so just relays it
        # note that udp request header is removed
        else:
            data = data[header_length:]
        if not data:
            return

        # relay the request using send-socket
        try:
            client.sendto(data, (server_addr, server_port))
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            if err in (errno.EINPROGRESS, errno.EAGAIN):
                pass
            else:
                shell.print_exception(e)

    # for a server to relay udp response
    def _handle_client(self, sock):

        # receive data from given sock
        data, r_addr = sock.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_client: data is empty')
            return
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))

        # server prepares response to relay
        # response is composed by data received
        # a remote server relays response to local server
        # 1. use common.pack_addr() to compose udp request header
        # this is because 'Each UDP datagram carries a UDP request header with it'
        # 2. add header before data to compose response
        # 3. encrypt all
        if not self._is_local:
            addrlen = len(r_addr[0])
            if addrlen > 255:
                # drop
                return
            data = pack_addr(r_addr[0]) + struct.pack('>H', r_addr[1]) + data
            response = encrypt.encrypt_all(self._password, self._method, 1,
                                           data)
            if not response:
                return

        # a local server relays response to local client
        # 1. decrypt data
        # 2. add first 3 bytes to compose a complete udp request header so as to compose response
        # this is because 'Each UDP datagram carries a UDP request header with it'
        else:
            data = encrypt.encrypt_all(self._password, self._method, 0,
                                       data)
            if not data:
                return
            header_result = parse_header(data)
            if header_result is None:
                return
            # addrtype, dest_addr, dest_port, header_length = header_result
            response = b'\x00\x00\x00' + data

        # relay the response
        # note how self._client_fd_to_server_addr is composed in _handle_server()
        # to conclude, client_addr is where a server receives request from
        # a local server receives request from local client
        # a remote server receives request from local server
        client_addr = self._client_fd_to_server_addr.get(sock.fileno())
        if client_addr:
            self._server_socket.sendto(response, client_addr)
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop

        server_socket = self._server_socket
        self._eventloop.add(server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR, self)
        loop.add_periodic(self.handle_periodic)

    def handle_event(self, sock, fd, event):
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                logging.error('UDP server_socket err')
            self._handle_server()
        elif sock and (fd in self._sockets):
            if event & eventloop.POLL_ERR:
                logging.error('UDP client_socket err')
            self._handle_client(sock)

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._server_socket.close()
                self._server_socket = None
                for sock in self._sockets:
                    sock.close()
                logging.info('closed UDP port %d', self._listen_port)
        self._cache.sweep()
        self._client_fd_to_server_addr.sweep()

    def close(self, next_tick=False):
        logging.debug('UDP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            for client in list(self._cache.values()):
                client.close()
