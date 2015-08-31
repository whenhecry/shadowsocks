#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2014-2015 clowwindy
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

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import socket
import struct
import re
import logging

from shadowsocks import common, lru_cache, eventloop, shell


CACHE_SWEEP_INTERVAL = 30

VALID_HOSTNAME = re.compile(br"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

common.patch_socket()

QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_AAAA = 28  # reference not found
QTYPE_CNAME = 5
QTYPE_NS = 2
QCLASS_IN = 1


# 3.1. Name space definitions
# Domain names in messages are expressed in terms of a sequence of labels.
# Each label is represented as a one octet length field followed by that
# number of octets.  Since every domain name ends with the null label of
# the root, a domain name is terminated by a length byte of zero.
#
# domain name is like F.ISI.ARPA
# labels of F.ISI.ARPA is like
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 20 |           1           |           F           |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 22 |           3           |           I           |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 24 |           S           |           I           |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 26 |           4           |           A           |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 28 |           R           |           P           |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 30 |           A           |           0           |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# ofcourse, lengths are converted to ASCII chars

# compose labels for a domain name
def build_address(address):
    # str.strip() remove leading and trailing b'.'
    # check http://stackoverflow.com/questions/6269765/what-does-the-b-character-do-in-front-of-a-string-literal
    # '' is normal text
    # in python2, the result is the same as if there's no prefix 'b'
    # >>> '.' == b'.'
    # True
    address = address.strip(b'.')

    labels = address.split(b'.')
    results = []

    # append octet length and label for each part
    for label in labels:
        l = len(label)

        # Label must be 63 characters or less.
        if l > 63:
            return None

        # length should be in the octet form, namely an ASCII char
        # common.chr() replaces builtin chr() for the difference in bytes, namely b'...' between python2/3
        # check common.py for reference
        results.append(common.chr(l))
        results.append(label)

    # append end 0
    # in python2, b'\0' = '\0'
    # check http://stackoverflow.com/questions/1182812/what-is-the-meaning-of-x00-x04-in-php
    # \x use two hexadecimal digits/one byte to repr x
    # so '\0' = '\x00'
    results.append(b'\0')

    return b''.join(results)

# rfc1035
# 4.1. Format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# 4.1.1. Header section format
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
# 4.1.2. Question section format
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                     QNAME                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QTYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QCLASS                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# compose a request
# only Header and Question are composed
def build_request(address, qtype):
    # compose Header
    # struct.pack() convert number/string to binary data with given format
    # '!' = big-endian, 'H' = unsigned short = 2Byte , 'B' = unsigned char = 1Byte
    # Header
    # ID is random
    # as a request, namely a query, 'QR' is set as 0
    # as a standard query, 'OPCODE' is set as 0
    # 'AA' is valid in responses so 0/1 both are OK, here is 0
    # 'TC' is set as 0 to specify message is not truncated
    # RD is set as 1 so recursion is desired
    # RA is valid in responses so 0/1 both are OK, here is 0
    # Z must be 0
    # RCODE is valid in responses so 0/1 both are OK, here is 0
    # QDCOUNT specifies the number of entries in the question, here is 1
    # ANCOUNT/NSCOUNT/ARCOUNT are valid in responses so 0/1 both are OK, here are 0
    request_id = os.urandom(2)
    header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)

    # compose Question
    # QNAME is a domain name represented as a sequence of labels
    # QTYPE may vary
    # QCLASS is always 1 for Internet
    addr = build_address(address)
    qtype_qclass = struct.pack('!HH', qtype, QCLASS_IN)

    return request_id + header + addr + qtype_qclass

# 4.1.3.
# ...
# RDATA           a variable length string of octets that describes the
#                 resource.  The format of this information varies
#                 according to the TYPE and CLASS of the resource record.
#                 For example, the if the TYPE is A and the CLASS is IN,
#                 the RDATA field is a 4 octet ARPA Internet address.

# compose str repr of domain name, with octet data and offset for RDATA given
# according to the info above, RDATA contains octet addr
# thus socket.inet_ntop canbe used to directly get ip from RDATA
def parse_ip(addrtype, data, length, offset):
    # socket.inet_ntop() convert a packed IP address to its string repr
    # ntop means network to printable
    if addrtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])

    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype in [QTYPE_CNAME, QTYPE_NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


# The pointer takes the form of a two octet sequence:
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# | 1  1|                OFFSET                   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
# The compression scheme allows a domain name in a message to be
# represented as either:
# - a sequence of labels ending in a zero octet
# - a pointer
# - a sequence of labels ending with a pointer

# compose complete labels with octet data and frontmost offset given
# note that data may contain pointer
# recursion inside
def parse_name(data, offset):

    # obtain the first byte pointed by offset
    # it is either a length octet followed by a label or another pointer or a termination
    # common.ord() converts it from ASCII char to number
    p = offset
    labels = []
    l = common.ord(data[p])

    # while not a termination
    while l > 0:
        # if the first byte is a pointer
        # dig into it, retrieve the innermost labels and append it as tail
        # then return directly
        # this is because pointer, if exists, is at the end of labels
        if (l & (128 + 64)) == (128 + 64):
            # pointer
            pointer = struct.unpack('!H', data[p:p + 2])[0]
            pointer &= 0x3FFF
            r = parse_name(data, pointer)
            labels.append(r[1])
            p += 2
            # pointer is the end
            return p - offset, b'.'.join(labels)

        # if the first byte is a length octet
        # append label according to length
        # then jump to the beginning of the next label
        else:
            labels.append(data[p + 1:p + 1 + l])
            p += 1 + l

        l = common.ord(data[p])

    # when termination is found, return labels and total length
    return p - offset + 1, b'.'.join(labels)

# 4.1.3. Resource record format
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# analyse either Question or Answer section according to given flag question
def parse_record(data, offset, question=False):
    nlen, name = parse_name(data, offset)

    # analyse Answer section
    if not question:
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]
        )

        # ip is the str repr of domain name
        # data may contain pointers
        # parse_name() is used to retrieve RDATA offset from data
        # then parse_ip() is used to get ip from RDATA
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)

        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)

    # analyse Question section
    else:
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)

# analyse Header
# note some fields are not used
def parse_header(data):
    if len(data) >= 12:
        header = struct.unpack('!HBBHHHH', data[:12])
        res_id = header[0]
        res_qr = header[1] & 128
        res_tc = header[1] & 2
        res_ra = header[2] & 128
        res_rcode = header[2] & 15
        # assert res_tc == 0
        # assert res_rcode in [0, 3]
        res_qdcount = header[3]
        res_ancount = header[4]
        res_nscount = header[5]
        res_arcount = header[6]
        return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
                res_ancount, res_nscount, res_arcount)

    # drop packet with incomplete header
    return None

# +---------------------+
# |        Header       | 
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs(resource records) answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+

# analyse a response
# note that all five parts are present
def parse_response(data):
    try:
        if len(data) >= 12:
            # analyse Header
            header = parse_header(data)
            if not header:
                return None
            res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
                res_ancount, res_nscount, res_arcount = header

            qds = []  # (name, None, record_type, record_class, None, None)
            ans = []  # (name, ip, record_type, record_class, record_ttl)
            offset = 12

            # extract all questions and answers, and store them
            # l is the length of either one Question or one Answer section
            # analyse Question section
            for i in range(0, res_qdcount):
                l, r = parse_record(data, offset, True)

                # update offset
                offset += l
                if r:
                    qds.append(r)

            # analyse Answer section
            for i in range(0, res_ancount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    ans.append(r)

            # not used
            for i in range(0, res_nscount):
                l, r = parse_record(data, offset)
                offset += l
            for i in range(0, res_arcount):
                l, r = parse_record(data, offset)
                offset += l

            response = DNSResponse()
            if qds:
                response.hostname = qds[0][0]  # name
            for an in qds:
                response.questions.append((an[1], an[2], an[3]))  # [(None, record_type, record_class)]
            for an in ans:
                response.answers.append((an[1], an[2], an[3]))  # [(ip, record_type, record_class)]
            return response
    except Exception as e:
        shell.print_exception(e)
        return None


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


class DNSResponse(object):
    def __init__(self):
        self.hostname = None
        self.questions = []  # [(addr, type, class)]
        self.answers = []  # [(addr, type, class)]

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


STATUS_IPV4 = 0
STATUS_IPV6 = 1


class DNSResolver(object):

    def __init__(self, server_list=None):
        self._loop = None
        self._hosts = {}
        self._hostname_status = {}
        self._hostname_to_cb = {}  # {hostname: [callback,...],...}
        self._cb_to_hostname = {}  # {callback: hostname}
        self._cache = lru_cache.LRUCache(timeout=300)
        self._sock = None
        if server_list is None:
            self._servers = None
            self._parse_resolv()
        else:
            self._servers = server_list
        self._parse_hosts()
        # TODO monitor hosts change and reload hosts
        # TODO parse /etc/gai.conf and follow its rules

    # set nameserver
    def _parse_resolv(self):
        self._servers = []

        # try to find nameserver from OS
        try:
            with open('/etc/resolv.conf', 'rb') as f:
                content = f.readlines()
                for line in content:
                    line = line.strip()
                    if line:
                        if line.startswith(b'nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                server = parts[1]
                                if common.is_ip(server) == socket.AF_INET:
                                    if type(server) != str:
                                        server = server.decode('utf8')
                                    self._servers.append(server)
        except IOError:
            pass

        # or use nameserver from Google
        if not self._servers:
            self._servers = ['8.8.4.4', '8.8.8.8']

    # exploit hosts file
    def _parse_hosts(self):
        etc_path = '/etc/hosts'
        if 'WINDIR' in os.environ:
            etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'

        # try to find hosts file from OS
        try:
            with open(etc_path, 'rb') as f:
                for line in f.readlines():
                    line = line.strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        if common.is_ip(ip):
                            for i in range(1, len(parts)):
                                hostname = parts[i]
                                if hostname:
                                    self._hosts[hostname] = ip
        except IOError:
            self._hosts['localhost'] = '127.0.0.1'

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        # TODO when dns server is IPv6
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        # dnsserver只作为发送请求的一个东西，是客户端，应该是client，所以没bind
        self._sock.setblocking(False)
        # 把自己的socket加到loop里面
        loop.add(self._sock, eventloop.POLL_IN, self)
        # 这里加入了handler，eventloop检测到socket有“动静”时调用self.handle_events
        loop.add_periodic(self.handle_periodic)

    def _call_callback(self, hostname, ip, error=None):
        # callbacks is a list of callbacks
        callbacks = self._hostname_to_cb.get(hostname, [])
        for callback in callbacks:
            if callback in self._cb_to_hostname:
                del self._cb_to_hostname[callback]
            if ip or error:
                # 实际调用发送数据的同时注册的回调函数callback
                callback((hostname, ip), error)
            else:
                callback((hostname, None),
                         Exception('unknown hostname %s' % hostname))
        if hostname in self._hostname_to_cb:
            del self._hostname_to_cb[hostname]
        if hostname in self._hostname_status:
            del self._hostname_status[hostname]

    def _handle_data(self, data):
        response = parse_response(data)
        if response and response.hostname:
            hostname = response.hostname
            ip = None
            for answer in response.answers:
                if answer[1] in (QTYPE_A, QTYPE_AAAA) and \
                        answer[2] == QCLASS_IN:
                    ip = answer[0]
                    break

            # dict.get(k[,d]) -> D[k] if k in D, else d
            if not ip and self._hostname_status.get(hostname, STATUS_IPV6) \
                    == STATUS_IPV4:
                self._hostname_status[hostname] = STATUS_IPV6
                self._send_req(hostname, QTYPE_AAAA)
            else:
                if ip:
                    self._cache[hostname] = ip  # store ip
                    # 这里调用回调_call_callback
                    self._call_callback(hostname, ip)  # ? callback
                elif self._hostname_status.get(hostname, None) == STATUS_IPV6:
                    for question in response.questions:
                        if question[1] == QTYPE_AAAA:
                            self._call_callback(hostname, None)
                            break

    def handle_event(self, sock, fd, event):
        # if socket doesn't belongs to dns, jump over
        if sock != self._sock:
            return

        # if error occurs, restart
        if event & eventloop.POLL_ERR:
            logging.error('dns socket err')
            self._loop.remove(self._sock)
            self._sock.close()
            # TODO when dns server is IPv6
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                       socket.SOL_UDP)
            self._sock.setblocking(False)
            self._loop.add(self._sock, eventloop.POLL_IN, self)
        # else, receive data
        else:
            # 因为是dns基于udp报文，所以没有连接要处理
            data, addr = sock.recvfrom(1024)
            if addr[0] not in self._servers:
                logging.warn('received a packet other than our dns')
                return
            self._handle_data(data)

    def handle_periodic(self):
        self._cache.sweep()

    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]
            arr = self._hostname_to_cb.get(hostname, None)
            if arr:
                arr.remove(callback)

                # if hostname is linked to only one callback
                if not arr:
                    del self._hostname_to_cb[hostname]
                    if hostname in self._hostname_status:
                        del self._hostname_status[hostname]

    def _send_req(self, hostname, qtype):
        req = build_request(hostname, qtype)
        for server in self._servers:
            logging.debug('resolving %s with type %d using server %s',
                          hostname, qtype, server)
            self._sock.sendto(req, (server, 53))

    # a callback caller
    # callback serves as an argument of the parent method
    # when the parent method is called and completes, the callback method is invoked
    # a callback usage example at https://en.wikipedia.org/wiki/Callback_(computer_programming)
    def resolve(self, hostname, callback):
        if type(hostname) != bytes:
            hostname = hostname.encode('utf8')

        # if hostname is None
        if not hostname:
            callback(None, Exception('empty hostname'))

        # or hostname is already a ip
        elif common.is_ip(hostname):
            callback((hostname, hostname), None)

        # or hostname is in hosts file
        elif hostname in self._hosts:
            logging.debug('hit hosts: %s', hostname)
            ip = self._hosts[hostname]
            callback((hostname, ip), None)

        # or hostname is in cache
        elif hostname in self._cache:
            logging.debug('hit cache: %s', hostname)
            ip = self._cache[hostname]
            callback((hostname, ip), None)

        # otherwise, resolve hostname
        else:
            # if hostname is invalid
            if not is_valid_hostname(hostname):
                callback(None, Exception('invalid hostname: %s' % hostname))
                return

            # arr is a list of callbacks
            arr = self._hostname_to_cb.get(hostname, None)

            # or
            if not arr:
                self._hostname_status[hostname] = STATUS_IPV4
                # 请求报文发出去
                self._send_req(hostname, QTYPE_A)
                # 同时在_hostname_to_cb注册一个{hostname:callback}的一对
                # 要hostname因为这个socket可以发出去很多不同hostname的解析请求
                self._hostname_to_cb[hostname] = [callback]
                self._cb_to_hostname[callback] = hostname
            else:
                arr.append(callback)
                # TODO send again only if waited too long
                self._send_req(hostname, QTYPE_A)

    def close(self):
        if self._sock:
            if self._loop:
                self._loop.remove_periodic(self.handle_periodic)
                self._loop.remove(self._sock)
            self._sock.close()
            self._sock = None


def test():
    dns_resolver = DNSResolver()
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop)

    global counter
    counter = 0

    # a closure
    # http://simeonfranklin.com/blog/2012/jul/1/python-decorators-in-12-steps/
    # key is, inner functions defined in non-global scope remember \
    # what their enclosing namespaces looked like at definition time
    # closures can be used to build custom functions
    # in this case, callback() remembers counter even if make_callback() has returned
    def make_callback():
        global counter

        def callback(result, error):
            global counter
            # TODO: what can we assert?
            print(result, error)
            counter += 1  # counter?
            if counter == 9:
                dns_resolver.close()
                loop.stop()
        a_callback = callback
        return a_callback

    assert(make_callback() != make_callback())

    dns_resolver.resolve(b'google.com', make_callback())
    dns_resolver.resolve('google.com', make_callback())
    dns_resolver.resolve('example.com', make_callback())
    dns_resolver.resolve('ipv6.google.com', make_callback())
    dns_resolver.resolve('www.facebook.com', make_callback())
    dns_resolver.resolve('ns2.google.com', make_callback())
    dns_resolver.resolve('invalid.@!#$%^&$@.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())

    loop.run()


if __name__ == '__main__':
    test()
