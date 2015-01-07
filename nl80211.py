#!/usr/bin/python2.7

import collections
import os
import random
import socket
import struct


class Iterator(object):
  def __init__(self, data):
    self.data = data
    self.offset = 0

  def __str__(self):
    data = self.data[self.offset:]
    return '(%d bytes): %r' % (len(data), data)

  def Advance(self, offset_incr):
    assert self.offset + offset_incr <= len(self.data)
    self.offset += offset_incr

  def Extract(self, length):
    assert self.offset + length <= len(self.data)
    ret = self.data[self.offset:self.offset + length]
    self.Advance(length)
    return ret

  def AtEnd(self):
    return self.offset == len(self.data)


class Accumulator(object):
  def __init__(self):
    self._parts = []

  def __str__(self):
    return ''.join(self._parts)

  def __len__(self):
    return sum(len(part) for part in self._parts)

  def Append(self, value):
    self._parts.append(value)


class SingleStructParser(struct.Struct):
  def Unpack(self, iterator, targetlen=None):
    if targetlen is not None:
      assert self.size == targetlen, 'Actual bytes: %d, expected bytes: %d' % (targetlen, self.size)
    values = self.unpack_from(iterator.data, iterator.offset)
    iterator.Advance(self.size)
    assert len(values) == 1
    return values[0]

  def Pack(self, accumulator, value):
    accumulator.Append(self.pack(value))


class StructParser(struct.Struct):
  def __init__(self, format, fields=None):
    super(StructParser, self).__init__(format)
    self._fields = fields

  def Unpack(self, iterator, targetlen=None):
    if targetlen is not None:
      assert self.size == targetlen, 'Actual bytes: %d, expected bytes: %d' % (targetlen, self.size)
    values = self.unpack_from(iterator.data, iterator.offset)
    iterator.Advance(self.size)
    return collections.OrderedDict(zip(self._fields, values))

  def Pack(self, accumulator, **values):
    ordered_values = []
    for field in self._fields:
      ordered_values.append(values[field])
    accumulator.Append(self.pack(*ordered_values))


class StringParser(object):
  def Unpack(self, iterator, targetlen):
    return iterator.Extract(targetlen)

  def Pack(self, accumulator, value):
    accumulator.Append(value)


class EmptyParser(object):
  def Unpack(self, iterator, targetlen=None):
    assert not targetlen
    return True

  def Pack(self, accumulator, value=None):
    pass


nlmsghdr = StructParser('LHHLL', ('length', 'type', 'flags', 'seq', 'pid'))
genlmsghdr = StructParser('BBH', ('cmd', 'version', 'reserved'))


class Attribute(object):
  _nlattr = StructParser('HH', ('len', 'type'))

  def __init__(self, attributes):
   super(Attribute, self).__init__()
   self._attributes = attributes

  def Unpack(self, iterator, targetlen=None):
    nlattr = self._nlattr.Unpack(iterator)
    if targetlen is not None:
      assert nlattr['len'] == targetlen
    name, sub_parser = self._attributes.get(nlattr['type'], (None, None))
    assert sub_parser, 'Unknown attribute type %d, len %d' % (nlattr['type'], nlattr['len'])
    sub_len = nlattr['len'] - self._nlattr.size
    ret = {
      name: sub_parser.Unpack(iterator, sub_len)
    }

    padding = ((nlattr['len'] + 4 - 1) & ~3) - nlattr['len']
    iterator.Advance(padding)

    return ret

  def Pack(self, accumulator, attrtype, **attrargs):
    sub_parser = self._attributes[attrtype][1]
    sub_accumulator = Accumulator()
    sub_parser.Pack(sub_accumulator, **attrargs)
    self._nlattr.Pack(accumulator, len=self._nlattr.size + len(sub_accumulator), type=attrtype)
    accumulator.Append(str(sub_accumulator))


class Attributes(object):
  def __init__(self, attributes):
    super(Attributes, self).__init__()
    self._attribute = Attribute(attributes)

  def Unpack(self, iterator, targetlen=None):
    if targetlen is not None:
      iterator = Iterator(iterator.Extract(targetlen))
    ret = collections.OrderedDict()
    while not iterator.AtEnd():
      ret.update(self._attribute.Unpack(iterator))
    return ret

  def Pack(self, accumulator, attrtype, **attrargs):
    return self._attribute.Pack(accumulator, attrtype, **attrargs)


flag = EmptyParser()
string = StringParser()
u8 = SingleStructParser('B')
u16 = SingleStructParser('H')
u32 = SingleStructParser('L')
u64 = SingleStructParser('Q')


rate_info = Attributes({
  1: ('bitrate', u16),
  2: ('mcs', u8),
  4: ('short_gi', flag),
  5: ('bitrate32', u32),
  9: ('80p80_mhz_width', u32),
  10: ('160_mhz_width', u32),
})

bss_param = Attributes({
  2: ('short_preamble', flag),
  3: ('short_slot_time', flag),
  4: ('dtim_period', u8),
  5: ('beacon_interval', u16),
})

sta_info = Attributes({
  1: ('inactive_time', u32),
  2: ('rx_bytes', u32),
  3: ('tx_bytes', u32),
  7: ('signal', u8),
  8: ('tx_bitrate', rate_info),
  9: ('rx_packets', u32),
  10: ('tx_packets', u32),
  11: ('tx_retries', u32),
  12: ('tx_failed', u32),
  13: ('signal_avg', u8),
  14: ('rx_bitrate', rate_info),
  15: ('bss_param', bss_param),
  16: ('connected_time', u32),
  17: ('sta_flags', StructParser('LL', ('mask', 'values'))),
  18: ('beacon_loss', u32),
  23: ('rx_bytes_64', u64),
  24: ('tx_bytes_64', u64),
})

nl80211_attr = Attributes({
  3: ('ifindex', u32),
  6: ('mac', string),
  21: ('sta_info', sta_info),
  46: ('generation', u32),
})

F_REQUEST = 1 << 0
F_MULTI = 1 << 1
F_ACK = 1 << 2
F_ECHO = 1 << 3
F_DUMP_INTR = 1 << 4

F_ROOT = 1 << 8
F_MATCH = 1 << 9
F_ATOMIC = 1 << 10
F_DUMP = F_ROOT | F_MATCH

CMD_GET_STATION = 17

STA_FLAG_AUTHORIZED = 1 << 0
STA_FLAG_SHORT_PREAMBLE = 1 << 1
STA_FLAG_WME = 1 << 2
STA_FLAG_MFP = 1 << 3
STA_FLAG_AUTHENTICATED = 1 << 4
STA_FLAG_TDLS_PEER = 1 << 5
STA_FLAG_ASSOCIATED = 1 << 6

ATTR_IFINDEX = 3


genquery = Accumulator()
nlmsghdr.Pack(
  genquery, 
  length=28, # XXX
  type=20, # XXX
  flags=F_REQUEST | F_ACK | F_DUMP,
  seq=random.randint(0, 2 ** 32 - 1),
  pid=os.getpid())
genlmsghdr.Pack(
  genquery,
  cmd=CMD_GET_STATION,
  version=0,
  reserved=0)
nl80211_attr.Pack(
  genquery,
  attrtype=ATTR_IFINDEX,
  value=6)

sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 16)
sock.bind((0,0))
sock.send(str(genquery))
data = sock.recv(4096)

iterator = Iterator(data)
print 'nlmsghdr: %s' % nlmsghdr.Unpack(iterator)
print 'genlmsghdr: %s' % genlmsghdr.Unpack(iterator)
print 'nl80211_attr: %s' % nl80211_attr.Unpack(iterator)
