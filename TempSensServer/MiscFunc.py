import struct
import time


def calc_crc(chrs):
    arc = struct.unpack("%dB" % len(chrs), chrs)
    csum = 0
    for c in arc:
        csum += c
    return csum & 0xff


def get_short_from_buf(buf):
    return struct.unpack("!H", buf[:2])[0]


def format_timestamp(timestamp):
    l_time = time.gmtime(timestamp + 8 * 60 * 60)
    return time.strftime("%Y-%m-%d %H:%M:%S", l_time)


