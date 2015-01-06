#!/usr/bin/python2.7

import collections
import socket
import struct

sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 16)
sock.bind((0,0))
query = '\34\0\0\0\24\0\5\3\\7\252T\367\16\0\0\21\0\0\0\10\0\3\0\6\0\0\0'
sock.send(query)
data = sock.recv(1024)


class ParsedData(object):
  def __init__(self, data):
    self.data = data
    self.offset = 0

  def __str__(self):
    data = self.data[self.offset:]
    return '(%d bytes): %r' % (len(data), data)

  def Advance(self, offset_incr):
    self.offset += offset_incr

  def AtEnd(self):
    return self.offset == len(self.data)


class Parser(struct.Struct):
  def __init__(self, format, fields=None):
    super(Parser, self).__init__(format)
    self._fields = fields

  def Parse(self, parsed_data, targetlen=None):
    if targetlen is not None:
      assert self.size == targetlen, 'Actual bytes: %d, expected bytes: %d' % (targetlen, self.size)
    values = self.unpack_from(parsed_data.data, parsed_data.offset)
    parsed_data.Advance(self.size)
    if self._fields:
    	return collections.OrderedDict(zip(self._fields, values))
    else:
        assert len(values) == 1
        return values[0]


class StringParser(object):
  def Parse(self, parsed_data, targetlen):
    ret = parsed_data.data[parsed_data.offset:parsed_data.offset + targetlen]
    parsed_data.Advance(targetlen)
    return ret


class EmptyParser(object):
  def Parse(self, parsed_data, targetlen=None):
    assert not targetlen
    return True


nlmsghdr = Parser('LHHLL', ('length', 'type', 'flags', 'seq', 'pid'))
genlmsghdr = Parser('BBH', ('cmd', 'version', 'reserved'))


class Attribute(object):
  _nlattr = Parser('HH', ('len', 'type'))

  def __init__(self, attributes):
   super(Attribute, self).__init__()
   self._attributes = attributes

  def Parse(self, parsed_data, targetlen=None):
    nlattr = self._nlattr.Parse(parsed_data)
    if targetlen is not None:
      assert nlattr['len'] == targetlen
    name, sub_parser = self._attributes.get(nlattr['type'], (None, None))
    assert sub_parser, 'Unknown attribute type %d, len %d' % (nlattr['type'], nlattr['len'])
    sub_len = nlattr['len'] - self._nlattr.size
    ret = {
      name: sub_parser.Parse(parsed_data, sub_len)
    }

    padding = ((nlattr['len'] + 4 - 1) & ~3) - nlattr['len']
    parsed_data.Advance(padding)

    return ret


class Attributes(object):

  def __init__(self, attributes):
    super(Attributes, self).__init__()
    self._attribute = Attribute(attributes)

  def Parse(self, parsed_data, targetlen=None):
    if targetlen is None:
      local_parsed_data = parsed_data
    else:
      local_parsed_data = ParsedData(parsed_data.data[parsed_data.offset:parsed_data.offset + targetlen])
      parsed_data.Advance(targetlen)
    ret = collections.OrderedDict()
    while not local_parsed_data.AtEnd():
      ret.update(self._attribute.Parse(local_parsed_data))
    return ret


flag = EmptyParser()
string = StringParser()
u8 = Parser('B')
u16 = Parser('H')
u32 = Parser('L')
u64 = Parser('Q')


sta_flag_authorized = 1 << 0
sta_flag_short_preamble = 1 << 1
sta_flag_wme = 1 << 2
sta_flag_mfp = 1 << 3
sta_flag_authenticated = 1 << 4
sta_flag_tdls_peer = 1 << 5
sta_flag_associated = 1 << 6

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
  17: ('sta_flags', Parser('LL', ('mask', 'values'))),
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

parsed_data = ParsedData(data)
print 'nlmsghdr: %s' % nlmsghdr.Parse(parsed_data)
print 'genlmsghdr: %s' % genlmsghdr.Parse(parsed_data)
print 'nl80211_attr: %s' % nl80211_attr.Parse(parsed_data)
