#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Intel Corporation
#

import sys, os, time, socket, subprocess, pipes, re, json, math
from array import array
from struct import Struct, unpack, unpack_from, pack, calcsize
from fcntl import ioctl
from subprocess import CalledProcessError
from tempfile import NamedTemporaryFile
from copy import copy, deepcopy
from collections import OrderedDict, namedtuple
from functools import reduce
from itertools import cycle
from argparse import (
    ArgumentParser, 
    SUPPRESS,
    FileType,
    RawDescriptionHelpFormatter
)

from ctypes import CDLL, create_string_buffer, get_errno, byref, cast, memset
from ctypes import POINTER, pointer, c_uint8, c_uint32, c_size_t, c_char_p
from ctypes.util import find_library

if sys.version_info.major == 3:
    # Python 3 imports
    from configparser import ConfigParser as SafeConfigParser
    from io import StringIO
    from socket import if_nametoindex, if_indextoname
    from os import sched_setaffinity, uname

elif sys.version_info.major == 2:
    # Python 2 imports
    from ConfigParser import SafeConfigParser
    from StringIO import StringIO

    lib = find_library('c')
    if not lib:
        lib = 'ld-musl-x86_64.so.1' # Alpine compatibility
    libc = CDLL(lib)

    def if_nametoindex(name): # type(str) -> int
        if not isinstance(name, str):
            raise TypeError('name must be a string.')
        ret = libc.if_nametoindex(name)
        if not ret:
            raise RuntimeError("Invalid Name")
        return ret

    def if_indextoname(index): # type: (int) -> str
        if not isinstance(index, int):
            raise TypeError ('index must be an int.')
        libc.if_indextoname.argtypes = [c_uint32, c_char_p]
        libc.if_indextoname.restype = c_char_p
        ifname = create_string_buffer(32)
        ifname = libc.if_indextoname(index, ifname)
        if not ifname:
            raise RuntimeError("Inavlid Index")
        return ifname

    def sched_setaffinity(pid, cpus): # type: (int, list[int]) -> None
        cpus = set(cpus)
        # 128 byte mutable buffer
        mask = create_string_buffer(_mask(cpus, 1024))
        size = len(mask)
        if libc.sched_setaffinity(c_uint32(pid), c_size_t(size), byref(mask)):
            raise Exception(os.strerror(get_errno()))


_VERSION_ = '3.0'

## public API

__all__ = [
    'Config', 'ConfigGlobals', 'ConfigSection', 
    'check_interface'
    ]

## example config files

_examples = {}

_examples["memcached"] = '''[globals]
# change the following line to match your CVL interface name
dev = eth4
busypoll = 50000
txadapt = off
txusecs = 0
rxadapt = off
rxusecs = 500
priority = skbedit

[memcd]
# launch memcached with the following options:
# --threads=6 --napi-ids=6
queues = 6
ports = 11211
'''

_examples["nginx"] = '''[globals]
# change the following line to match your CVL interface name
dev = eth4
busypoll = 10000
txadapt = off
txusecs = 0
rxadapt = off
rxusecs = 500
priority = skbedit

[nginx]
# launch nginx with the following option:
# -g "worker_processes 6;"
pollers = 2
queues = 6
ports = 80,443
'''

_examples["redis"] = '''[globals]
# change the following line to match your CVL interface name
dev = eth4
busypoll = 10000
txadapt = off
txusecs = 0
rxadapt = off
rxusecs = 500
priority = skbedit

[redis]
# launch six redis instances on ports 6379 through 6384
mode = shared
queues = 6
ports = 6379-6384
'''

_examples["multi-app"] = '''[globals]
# change the following line to match your CVL interface name
dev = eth4
busypoll = 10000
txadapt = off
txusecs = 0
rxadapt = off
rxusecs = 500
priority = skbedit

[memcd]
# launch memcached with the following options:
# --threads=2 --napi-ids=2
queues = 2
ports = 11211

[redis]
# launch two redis instances on ports 6379 and 6380
mode = shared
queues = 2
ports = 6379-6380

[nginx]
# launch nginx with the following option:
# -g "worker_processes 2;"
queues = 2
ports = 80,443
'''

## .service unit template

_service_unit = '''[Unit]
Description=ADQ Setup for %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/adqsetup --log=/var/lib/adqsetup/%i.log apply /var/lib/adqsetup/%i.conf

[Install]
WantedBy=multi-user.target
'''

## private functions


def _printhead(s, code=0):
    # type: (str, str) -> None
    ''' 
    Print a header line with a bold font and optional color code
    '''
    if sys.stdin.isatty():
        # if code:
        print("\n\x1B[%dm**\x1B[1m " % code + str(s) + 
            " \x1B[0m\x1B[%dm**\x1B[0m" % code)
        # else:
        #     print("\n** \x1B[1m" + str(s) + "\x1B[0m **")
    else:
        print("\n** " + str(s) + " **")

def _hexstr(data): # type: (bytes) -> str
    if data is None:
        return 'None'
    if not isinstance(data, bytearray):
        data = bytearray(data)
    return ''.join('{:02x}'.format(x) for x in data)

def _pack_list(lst, code='B', length=None):
    # type: (list, str, int) -> bytes
    if not length:
        length = len(lst)
    else:
        lst = lst[:length]
        if len(lst) < length:
            lst = lst + [0] * (length - len(lst))
    return pack("%d%s" % (len(lst), code), *lst)

def _exec(args, shell=False, check=False, log=None, echo=False):
    # type: (list, bool, bool, any, bool) -> any
    '''
    Spawn a process, directly or through the shell and capture output
    returns output or success
    '''
    success = True
    stdout = None
    if isinstance(args, list):
        args = [str(s) for s in args]
    else:
        args = [args]

    try:
        stdout = subprocess.check_output(
            args, shell=shell, stderr=subprocess.STDOUT
        ) 
    except CalledProcessError as err:
        if sys.version[:1] == '3':
            output = err.output.decode().strip()
        else:
            output = err.output.strip()
        if not check: 
            raise
        if echo:
            print(output)
        success = False

    if log and success:
        if len(args) > 1:
            command = ' '.join([pipes.quote(s) for s in args])
        else:
            command = args[0]
        log.write("%s\n" % command)

    if stdout is not None:
        if sys.version_info.major == 3:
            stdout = stdout.decode().strip()
        else:
            stdout = stdout.strip()

    if stdout and echo:
        print(stdout)

    if check:
        return success
    else:
        return stdout

def _mask(bits, size=8): # type (set[int]. int) -> bytes
    bits = set(bits)
    mask = array('B', [0] * int(math.ceil(size / 8)))
    for index in bits:
        if index > size - 1:
            raise Exception(
                "bit mask index cannot be more than %d" % (size - 1,)
            )
        bmask = 1 << (index % 8)
        index = int(index / 8)
        mask[index] = mask[index] | bmask
    if sys.version_info.major == 3:
        return mask.tobytes()
    else:
        return bytes(mask.tostring())

def _readfile(path): # type: (list[str]) -> str
    if not os.path.isfile(path):
        raise Exception("%r not found" % path)
    with open(path, 'r') as f:
        return f.read().strip()

def _writefile(path, data): # type(list[str], str) -> int
    if not os.path.isdir(os.path.dirname(path)):
        os.mkdir(os.path.dirname(path))
    with open(path, 'w') as f:
        return f.write(data)

def _sysctl(key, value=None, log=None):
    # type: (str, any, any) -> str | dict[str, str]
    '''
    Get or set a sysctl value by key
    '''
    path = os.path.join(*(['/proc', 'sys'] + key.split('.')))
    if value is None:
        if os.path.isdir(path):
            results = {}
            for root, _, files in os.walk(path):
                for f in files:
                    key = '.'.join(root.replace(path, '')\
                        .split(os.sep)[1:] + [f])
                    try:
                        results[key] = _readfile(os.path.join(root, f))
                    except IOError:
                        pass
            return results
        else:
            return _readfile(path)
    else:
        if log:
            log.write("sysctl --write %s=%s\n" % (key, str(value)))
        return _writefile(path, value)

def _uevent(dev, subdev=""):
    # type: (str, str) -> dict
    '''
    Get and parse device/uevent entry for device
    '''
    path = os.path.join(*['/sys', 'class', 'net', dev, 'device', subdev, 'uevent'])
    info = dict(re.findall('^([\w\_]+)=(.*)$', _readfile(path), re.MULTILINE))
    return {key.lower(): val for key, val in info.items()}

def _is_vf(dev):
    # type: (str) -> bool
    path = os.path.join(*['/sys', 'class', 'net', dev, 'device', 'physfn'])
    return os.path.islink(path)

def _vf_to_pf(dev):
    # type: (str) -> str
    pf_pci = _uevent(dev, "physfn")["pci_slot_name"]
    netdevs = os.listdir(os.path.join(*['/sys', 'class', 'net']))
    for n in netdevs:
        try:
            if _uevent(n)["pci_slot_name"] == pf_pci:
                return n
        except:
            pass
    return None

def _irqs(dev):
    # get nic interrupts
    # named: (ice|iavf)-<dev>-TxRx-<queue>
    output = _exec(
        "grep -iE '(ice|iavf)-%s-TxRx-' /proc/interrupts | cut -f1 -d:" % dev, 
        shell=True
    )
    return [int(t) for t in output.split()]

def _proc_status(pid):
    # type: (int) -> dict
    with open('/proc/' + str(pid) + '/status', 'r') as fp:
        lines = fp.read().strip().split('\n')
        return dict([l.split(':\t') for l in lines if len(l.split(':\t')) > 1])

def _ps(filter=None):
    # type: (str) -> list
    results = []
    for dir in os.listdir('/proc'):
        if 'self' not in dir and os.path.isfile('/proc/' + dir + '/status'):
            pid = int(dir)
            status = _proc_status(pid)
            if filter is not None:
                if filter in status['Name']:
                    results.append(pid)
            else:
                results.append(pid)
    return results

def _napi_threads(dev):
    # type: (str) -> list[int]
    return list(reversed(_ps("napi/%s" % dev)))


## nettools abstraction

class classproperty(object):
  def __init__(self, fget):
    self.fget = fget
  def __get__(self, instance, owner):
    return self.fget(owner)
  def __set__(self, instance, value):
    raise AttributeError("can't set attribute")

class StructTempl(object):
    _struct = ""
    _regex = r"((\d*)([xcbB\?hHiIlLqQfdsSpPaA])|{\w*})"
    @classproperty
    def _pattern(self): # type: () -> str
        p = self._struct
        for n in re.findall(r"{(\w*)}", p):
            p = p.replace("{%s}" % n, globals()[n]._pattern)
        return p.replace('S', 's').replace('A', 'I').replace('a', 'H')
    @classproperty
    def _size(cls): # type: () -> int
        return calcsize(cls._pattern)
    @classproperty
    def _types(cls): # type: () -> tuple[tuple[str,str,int]]
        items = []
        for e, c, t in re.findall(cls._regex, cls._struct):
            c = int(c) if c else 1
            if e[0] == '{': # subclass
                items.append(tuple([None, e[1:-1], c]))
            elif t != 'x':
                items.append(tuple([t, None, c]))
        return tuple(items)
    @classproperty
    def _size_ftuple(cls): # type: () -> int
        count = 0
        for t, e, c in cls._types:
            if e:
                count += globals()[e]._size_ftuple
            elif c > 1 and t not in ['s', 'S', 'x']:
                count += c
            elif t != 'x':
                count += 1
        return count
    @classmethod
    def _from_ftuple(cls, values): # type: (tuple) -> StructTempl
        items = []
        values = list(values)
        for t, e, c in cls._types:
            if e: # subpattern
                obj = globals()[e]
                c = obj._size_ftuple
                items.append(obj._from_ftuple(values[:c]))
                del values[:c]
            elif c > 1 and t not in ['s', 'S', 'x']: # tuple
                items.append(tuple(values[:c]))
                del values[:c]
            elif t != 'x': # single value
                value = values.pop(0)
                if t == 'S': # string
                    value = value.strip(b'\x00')
                    if sys.version_info.major == 3:
                        value = value.decode()
                elif t == 'a': # ipv4 port
                    value = socket.ntohs(value)
                elif t == 'A': # ipv4 address
                    value = socket.ntohl(value)
                items.append(value)
        return cls(*items)
    @classmethod
    def _from(cls, data, offset=0): # type: (bytes, int) -> StructTempl
        return cls._from_ftuple(unpack_from(cls._pattern, data, offset))
    @classmethod
    def _blank(cls): # type: () -> StructTempl
        return cls._from(bytes(bytearray(cls._size)))
    @property
    def _ftuple(self): # type: () -> tuple
        fields = list(self._fields)
        items = []
        for t, e, c in self._types:
            if e: # subpattern
                items.extend(getattr(self, fields.pop(0))._ftuple)
            elif c > 1 and t not in ['s', 'S', 'x']: # tuple
                items.extend(getattr(self, fields.pop(0)))
            elif t != 'x': # single value
                value = getattr(self, fields.pop(0))
                if t == 'S' and sys.version_info.major == 3: # string
                    value = value.encode()
                elif t == 'a': # ipv4 port
                    value = socket.htons(value)
                elif t == 'A': # ipv4 address
                    value = socket.htonl(value)
                items.append(value)
        return tuple(items)
    @property
    def _bytes(self): # type: () -> bytes
        return pack(self._pattern, *self._ftuple)
    @property
    def _dict(self): # type: () -> dict
        result = {}
        for n in self._fields:
            obj = getattr(self, n)
            if hasattr(obj, "_dict"):
                result[n] = obj._dict
            else:
                result[n] = obj
        return result

class FeaturesGetBlock(StructTempl, namedtuple("FeaturesGetBlock", 
        "available requested active unchanged")):
    _struct = "IIII"

class FeaturesSetBlock(StructTempl, namedtuple("FeaturesSetBlock", 
        "mask value")):
    _struct = "II"

class RXnfcFlowExt(StructTempl, namedtuple("RXnfcFlowExt",
            "h_dest vlan_etype vlan_tci data")):
    _struct = "2x6BHH2I"

class RXnfcFlowAddr(StructTempl, namedtuple("RXnfcFlowAddr",
            "src dst src_port dst_port")):
    _struct = "AAaa40x"

class RXnfcFlow(StructTempl, namedtuple("RXnfcFlow",
            "proto addr ext addr_mask ext_mask "
            "ring id")):
    _struct = "I{RXnfcFlowAddr}{RXnfcFlowExt}{RXnfcFlowAddr}{RXnfcFlowExt}QI4x"

class RXnfc(StructTempl, namedtuple("RXnfc", "cmd type data flow count")):
    _struct = "IIQ{RXnfcFlow}I"

class Ethtool(object):
    ## include/uapi/linux/if.h
    IFNAMSIZ = 16
    ## include/uapi/linux/sockios.h
    SIOCETHTOOL = 0x8946        
    ## include/uapi/linux/ethtool.h
    MAX_NUM_QUEUE = 4096
    QUEUE_MASK_SIZE = int(math.ceil(MAX_NUM_QUEUE / 8))
    ETH_GSTRING_LEN = 32
    CMD_GCOALESCE   = 0x0000000e # /* Get coalesce config */
    CMD_SCOALESCE   = 0x0000000f # /* Set coalesce config. */
    CMD_GRINGPARAM  = 0x00000010 # /* Get ring parameters */
    CMD_SRINGPARAM  = 0x00000011 # /* Set ring parameters. */
    CMD_GSTRINGS    = 0x0000001b
    CMD_GSTATS      = 0x0000001d
    CMD_RESET       = 0x00000034
    CMD_GSSET_INFO  = 0x00000037
    CMD_GPFLAGS     = 0x00000027 # /* Get driver-private flags bitmap */
    CMD_SPFLAGS     = 0x00000028 # /* Set driver-private flags bitmap */
    CMD_GRXCLSRLCNT = 0x0000002e # /* Get RX class rule count */
    CMD_GRXCLSRULE  = 0x0000002f # /* Get RX classification rule */
    CMD_GRXCLSRLALL = 0x00000030 # /* Get all RX classification rule */
    CMD_SRXCLSRLDEL = 0x00000031 # /* Delete RX classification rule */
    CMD_SRXCLSRLINS = 0x00000032 # /* Insert RX classification rule */
    CMD_SRXNTUPLE   = 0x00000035 # /* Add an n-tuple filter to device */
    CMD_GFEATURES   = 0x0000003a # /* Get device offload settings */
    CMD_SFEATURES   = 0x0000003b # /* Change device offload settings */
    CMD_GCHANNELS   = 0x0000003c # /* Get no of channels */
    CMD_SCHANNELS   = 0x0000003d # /* Set no of channels */    
    CMD_PERQUEUE    = 0x0000004b # /* Set per queue options */    
    ETH_SS_STATS          = 1
    ETH_SS_PRIV_FLAGS     = 2
    ETH_SS_NTUPLE_FILTERS = 3
    ETH_SS_FEATURES       = 4
    RXNTUPLE_ACTION_DROP  = -1 # /* drop packet */
    RXNTUPLE_ACTION_CLEAR = -2
    ETH_RESET_FILTER    = 1 << 3
    ETH_RESET_DEDICATED = 0x0000ffff
    ETH_RESET_ALL       = 0xffffffff
    RX_CLS_LOC_SPECIAL = 0x80000000 # /* flag */
    RX_CLS_LOC_ANY     = 0xffffffff
    RX_CLS_LOC_FIRST   = 0xfffffffe
    RX_CLS_LOC_LAST    = 0xfffffffd
    TCP_V4_FLOW = 0x01
    UDP_V4_FLOW = 0x02

    # struct ethtool_rxnfc {
    #     __u32               cmd;
    #     __u32               flow_type;
    #     __u64               data;
    #     struct ethtool_rx_flow_spec fs;
    #     union {
    #         __u32           rule_cnt;
    #         __u32           rss_context;
    #     };
    #     __u32               rule_locs[0];
    # };

    def __init__(self, ifname, log=None): # type: (str, any) -> None
        self.ifname = ifname
        self.ifindex = if_nametoindex(ifname)
        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP
        )
        self.log = log
        self._rule_id = None

    def _ioctl(self, data): # type: (bytearray|str|bytes) -> bytes
        buf = array('B', bytearray(data))
        addr = buf.buffer_info()[0]
        if sys.version_info.major == 3:
            ifname = self.ifname.encode()
        else:
            ifname = self.ifname
        msg = array('B', bytearray(pack("16sP", ifname, addr)))
        ioctl(
            self.socket.fileno(), self.SIOCETHTOOL, msg, 1
        )
        if sys.version_info.major == 3:
            return buf.tobytes()
        else:
            return buf.tostring()

    def _log(self, *args): # type: (...) -> None
        if self.log:
            for a in args:
                self.log.write(str(a) + '\n')

    def reset(self):
        self._ioctl(pack("2I", self.CMD_RESET, self.ETH_RESET_DEDICATED))

    def _strings_get(self, id): # type: (int) -> list[str]
        results = []
        resp = self._ioctl(pack("2IQI", self.CMD_GSSET_INFO, 0, 1 << id, 0))
        mask, length = unpack_from("8xQI", resp)
        if mask == 0:
            length = 0
        data = bytearray(pack("3I", self.CMD_GSTRINGS, id, length))
        data.extend(b'\x00' * length * self.ETH_GSTRING_LEN)
        resp = self._ioctl(data)
        for i in range(length):
            offset = 12 + (self.ETH_GSTRING_LEN * i)
            s = unpack_from("%ds" % self.ETH_GSTRING_LEN, resp, offset)[0]
            s = s.replace(b'\x00', b'')
            if sys.version_info.major == 3:
                s = s.decode()
            # if len(s) < 1:
            #     print(_hexstr(data[offset:offset+self.ETH_GSTRING_LEN]))
            results.append(s)
        return results

    def _features_get(self, strings=None): 
        # type: (list[str]) -> dict[str, bool]
        results = {}
        if strings is None:
            strings = self._strings_get(self.ETH_SS_FEATURES)
        blocks = int(math.ceil(len(strings) / 32.0))
        data = bytearray(pack('2I', self.CMD_GFEATURES, blocks))
        for i in range(blocks):
            data.extend(FeaturesGetBlock(*([0] * 4))._bytes)
        resp = self._ioctl(data)
        offset = 8
        for i in range(unpack_from('2I', resp)[1]):
            value = FeaturesGetBlock._from(resp, offset)
            offset += value._size
            for j in range(32):
                index = (i * 32) + j
                if index >= len(strings):
                    break
                if len(strings[index]):
                    results[strings[index]] = True \
                        if value.active & (1 << j) else False
        return results

    def _features_set(self, modify, strings=None): 
        # type: (dict[str, bool], list[str]) -> int
        if strings is None:
            strings = self._strings_get(self.ETH_SS_FEATURES)
        blocks = int(math.ceil(len(strings) / 32.0))
        mask = array('I', [0] * blocks)
        value = array('I', [0] * blocks)
        for n, v in modify.items():
            if len(n) < 1 or n not in strings:
                raise Exception("invalid feature: %r" % n)
            index = strings.index(n)
            bmask = 1 << (index % 32)
            index = int(index / 32)
            mask[index] = mask[index] | bmask
            if v:
                value[index] = value[index] | bmask
            else:
                value[index] = value[index] & ~bmask
        data = bytearray(pack('2I', self.CMD_SFEATURES, blocks))
        for i in range(blocks):
            data.extend(FeaturesSetBlock(mask[i], value[i])._bytes)
        return self._ioctl(data)

    def features(self, modify=None): 
        # type: (dict[str, bool]) -> dict[str, bool]
        strings = self._strings_get(self.ETH_SS_FEATURES)
        if modify and len(modify):
            self._features_set(modify, strings)
            for n, v in modify.items():
                self._log("ethtool --features %s %s %s" \
                    % (self.ifname, n, 'on' if v else 'off'))
        return self._features_get(strings)

    def _flags_get(self, strings=None): # type: (list[str]) -> dict[str, bool]
        results = {}
        if strings is None:
            strings = self._strings_get(self.ETH_SS_PRIV_FLAGS)
        data = bytearray(pack('II', self.CMD_GPFLAGS, 0))
        resp = self._ioctl(data)
        flags = unpack_from('I', resp, 4)[0]
        for i in range(32):
            if i >= len(strings):
                break
            if len(strings[i]):
                results[strings[i]] = True if flags & (1 << i) else False        
        return results

    def _flags_set(self, modify, strings=None): 
        # type: (dict[str, bool], list[str]) -> None
        if strings is None:
            strings = self._strings_get(self.ETH_SS_PRIV_FLAGS)
        data = bytearray(pack('II', self.CMD_GPFLAGS, 0))
        resp = self._ioctl(data)
        flags = unpack_from('I', resp, 4)[0]
        for n, v in modify.items():
            if len(n) < 1 or n not in strings:
                    raise Exception("invalid private flag: %r" % n)
            index = strings.index(n)
            bmask = 1 << (index % 32)
            if v:
                flags = flags | bmask
            else:
                flags = flags & ~bmask            
        data = bytearray(pack('II', self.CMD_SPFLAGS, flags))
        self._ioctl(data)

    def flags(self, modify=None): 
        # type: (dict[str, bool]) -> dict[str, bool]
        strings = self._strings_get(self.ETH_SS_PRIV_FLAGS)
        if modify and len(modify):
            self._flags_set(modify, strings)
            for n, v in modify.items():
                self._log("ethtool --set-priv-flags %s %s %s" \
                    % (self.ifname, n, 'on' if v else 'off'))
        return self._flags_get(strings)

    def _queue_mask(self, queues): # type (set[int]) -> bytearray
        mask = array('I', [0] * int(math.ceil(self.MAX_NUM_QUEUE / 8) / 4))
        for index in queues:
            if index > self.MAX_NUM_QUEUE:
                raise Exception(
                    "queue index cannot be more than %d" \
                        % self.MAX_NUM_QUEUE - 1
                )
            bmask = 1 << (index % 32)
            index = int(index / 32)
            mask[index] = mask[index] | bmask
        if sys.version_info.major == 3:
            return bytearray(mask.tobytes())
        else:
            return bytearray(mask.tostring())

    class _coalesce_params(StructTempl, namedtuple("_coalesce_params", 
            "rx_usecs rx_frames rx_usecs_irq rx_frames_irq "
            "tx_usecs tx_frames tx_usecs_irq tx_frames_irq "
            "stats_usecs adaptive_rx adaptive_tx rate_low "
            "rx_usecs_low rx_frames_low tx_usecs_low tx_frames_low "
            "rate_high rx_usecs_high rx_frames_high tx_usecs_high "
            "tx_frames_high rate_interval")):
        _struct = "IIIIIIIIIIIIIIIIIIIIII"

    def _coalecse_get(self): 
        # type: () -> Ethtool._coalesce_params
        data = bytearray(pack('I', self.CMD_GCOALESCE))
        data.extend(self._coalesce_params._blank()._bytes)
        resp = self._ioctl(data)
        return self._coalesce_params._from(resp, 4)

    def _coalecse_set(self, params): 
        # type: (Ethtool._coalesce_params) -> None
        data = bytearray(pack('I', self.CMD_SCOALESCE))
        data.extend(params._bytes)
        self._ioctl(data)

    def coalesce(self, params=None):
        # type: (Ethtool._coalesce_params) -> Ethtool._coalesce_params
        if params is not None:
            self._coalecse_set(params)
            if self.log:
                params = params._asdict()
                for n in ['adaptive_rx', 'rx_usecs', 'adaptive_tx', 'tx_usecs']:
                    v = params[n]
                    if isinstance(v, bool):
                        v = 'on' if v else 'off'
                    self._log("ethtool --coalesce %s %s %s" % 
                        (self.ifname, n.replace('_', '-'), v))
        return self._coalecse_get()

    def _coalesce_queues_get(self, queues):
        # type: (set[int]) -> list[Ethtool._coalesce_params]
        ssize = self._coalesce_params._size
        data = bytearray(
            pack('2I', self.CMD_PERQUEUE, self.CMD_GCOALESCE)
        )
        mask = self._queue_mask(queues)
        data.extend(mask)
        for _ in range(len(queues)):
            data.extend(pack('I', self.CMD_GCOALESCE))
            data.extend(self._coalesce_params._blank()._bytes)
        resp = self._ioctl(data)
        offset = 8 + len(mask) + 4
        results = []
        for _ in range(len(queues)):
            obj = self._coalesce_params._from(resp, offset)
            results.append(obj)
            offset += obj._size + 4
        return results

    def _coalecse_queues_set(self, queues, params):
        # type: (set[int], list[Ethtool._coalesce_params]) -> None
        data = bytearray(
            pack('2I', self.CMD_PERQUEUE, self.CMD_SCOALESCE)
        )
        data.extend(self._queue_mask(queues))
        for i in range(len(queues)):
            data.extend(pack('I', self.CMD_SCOALESCE))
            data.extend(params[i]._bytes)
        self._ioctl(data)

    def coalesce_queues(self, queues, params=None):
        # type: (set[int], list[any]) -> list[Ethtool._coalesce_params]
        if params is not None:
            self._coalecse_queues_set(queues, params)
            if self.log:
                params = params[0]._asdict()
                for n in ['adaptive_rx', 'rx_usecs', 'adaptive_tx', 'tx_usecs']:
                    v = params[n]
                    if isinstance(v, bool):
                        v = 'on' if v else 'off'
                    mask = self._queue_mask(queues)
                    mask.reverse()
                    mask = _hexstr(mask).lstrip('0')
                    self._log(
                        "ethtool --per-queue %s queue_mask 0x%s"
                        " --coalesce %s %s" % 
                        (self.ifname, mask, n.replace('_', '-'), v)
                    )
        return self._coalesce_queues_get(queues)

    class _ring_params(StructTempl, namedtuple("_ring_params", 
            "rx_max rx_mini_max rx_jumbo_max tx_max "
            "rx rx_mini rx_jumbo tx")):
        _struct = "IIIIIIII"

    def _rings_get(self): # type: () -> Ethtool._ring_params
        data = bytearray(pack('I', self.CMD_GRINGPARAM))
        data.extend(self._ring_params(*([0] * 8))._bytes)
        resp = self._ioctl(data)
        return self._ring_params._from(resp, 4)

    def _rings_set(self, params): # type: (Ethtool._ring_params) -> None
        data = bytearray(pack('I', self.CMD_SRINGPARAM))
        data.extend(params._bytes)
        self._ioctl(data)

    def rings(self, params=None):
        # type: (Ethtool._ring_params) -> Ethtool._ring_params
        if params is not None:
            rings = self._rings_get()
            if params.rx > rings.rx_max:
                params = params._replace(rx=rings.rx_max)
            if params.tx > rings.tx_max:
                params = params._replace(rx=rings.tx_max)
            self._rings_set(params)
            self._log("ethtool --set-ring %s rx %d tx %d" % 
                (self.ifname, params.rx, params.tx))
        return self._rings_get()

    @property
    def _ntuple_count(self):
        # type: () -> int
        resp = self._ioctl(RXnfc(self.CMD_GRXCLSRLCNT, 0, 0, 
            RXnfcFlow._blank(), 0)._bytes)
        return RXnfc._from(resp).count

    @property
    def _ntuple_max(self):
        # type: () -> int
        resp = self._ioctl(RXnfc(self.CMD_GRXCLSRLCNT, 0, 0, 
            RXnfcFlow._blank(), 0)._bytes)
        return RXnfc._from(resp).data - 1
    
    @property
    def _ntuple_next(self):
        if self._rule_id is None:
            self._rule_id = self._ntuple_max
        else:
            self._rule_id -= 1
        return self._rule_id

    @property
    def _ntuple_ids(self):
        # type: () -> tuple[int]
        count = self._ntuple_count
        ids = tuple()
        if count:
            resp = self._ioctl(
                RXnfc(
                    self.CMD_GRXCLSRLALL, 0, 0, 
                    RXnfcFlow._blank(), count
                )._bytes + 
                bytearray(4 * count)
            )
            ids = unpack_from("%dI" % count, resp, RXnfc._size)
        return ids

    def ntuple_list(self, modify=None):
        # type: (dict[int, RXnfcFlow]) -> dict[int, RXnfcFlow]
        proto_map = {
            self.TCP_V4_FLOW: 'tcp',
            self.UDP_V4_FLOW: 'udp'
        }
        results = OrderedDict()
        for id in reversed(self._ntuple_ids):
            resp = self._ioctl(RXnfc(
                self.CMD_GRXCLSRULE, 0, 0, 
                RXnfcFlow._blank()._replace(id=id), 0
                )._bytes)
            flow = RXnfc._from(resp).flow._dict
            flow['proto'] = proto_map[flow['proto']]
            results[id] = flow
        return results

    def ntuple_add(self, proto='tcp', src_port=0, dst_port=0, action=0, id=None):
        # type: (str, int, int, int, int) -> int
        proto_map = {
            'tcp': self.TCP_V4_FLOW,
            'udp': self.UDP_V4_FLOW
        }
        if proto.lower() not in proto_map:
            raise Exception("invalid proto %r" % proto)
        src_port_mask = 0xffff if src_port else 0
        dst_port_mask = 0xffff if dst_port else 0
        if id is None:
            id = self._ntuple_next
        flow = RXnfcFlow(
            proto_map[proto.lower()],
            RXnfcFlowAddr(0, 0, src_port, dst_port),
            RXnfcFlowExt._blank(),
            RXnfcFlowAddr(0, 0, src_port_mask, dst_port_mask),
            RXnfcFlowExt._blank(), action, id
        )
        resp = self._ioctl(RXnfc(
            self.CMD_SRXCLSRLINS, 0, 0, 
            flow, 1
        )._bytes)
        self._log(
            "ethtool --config-ntuple %s flow-type %s4 dst-port %d action %d" % 
            (self.ifname, proto.lower(), dst_port, action)
        )
        return RXnfc._from(resp).flow.id

    class _channels_params(StructTempl, namedtuple("_channel_params", 
            "max_rx max_tx max_other max_combined "
            "rx tx other combined")):
        _struct = "IIIIIIII"

    def _channels_get(self): 
        # type: () -> Ethtool._channels_params
        data = bytearray(pack('I', self.CMD_GCHANNELS))
        data.extend(self._channels_params(*([0] * 8))._bytes)
        resp = self._ioctl(data)
        return self._channels_params._from(resp, 4)

    def _channels_set(self, params): 
        # type: (Ethtool._channels_params) -> None
        data = bytearray(pack('I', self.CMD_SCHANNELS))
        data.extend(params._bytes)
        self._ioctl(data)

    def channels(self, params=None): 
        # type: (Ethtool._channels_params) -> Ethtool._channels_params
        if params is not None:
            channels = self._channels_get()
            if params.combined > channels.max_combined:
                params = params._replace(combined=channels.max_combined)
            if params.rx > channels.max_rx:
                params = params._replace(rx=channels.max_rx)
            if params.tx > channels.max_tx:
                params = params._replace(tx=channels.max_tx)
            self._channels_set(params)
        return self._channels_get()

    def stats(self): # type: () -> dict[str, int]
        strings = self._strings_get(self.ETH_SS_STATS)
        results = {}
        data = bytearray(pack("II", self.CMD_GSTATS, len(strings)))
        data.extend(bytearray(len(strings) * 8))
        resp = self._ioctl(data)
        for i in range(len(strings)):
            value = unpack_from('Q', resp, 8 + (i * 8))[0]
            results[strings[i]] = value
        return results

class NLAttr(namedtuple("NLAttr", "type data")):
    ## include/uapi/linux/netlink.h
    # struct nlattr {
    #     __u16           nla_len;
    #     __u16           nla_type;
    # };
    FLAG_NESTED    = (1 << 15)
    FLAG_BYTEORDER = (1 << 14) # Network byte order
    TYPE_MASK      = ~(FLAG_NESTED | FLAG_BYTEORDER)
    TYPE_INVALID      = 0
    TYPE_FLAG         = 1
    TYPE_U8           = 2
    TYPE_U16          = 3
    TYPE_U32          = 4
    TYPE_U64          = 5
    TYPE_S8           = 6
    TYPE_S16          = 7
    TYPE_S32          = 8
    TYPE_S64          = 9
    TYPE_BINARY       = 10
    TYPE_STRING       = 11
    TYPE_NUL_STRING   = 12
    TYPE_NESTED       = 13
    TYPE_NESTED_ARRAY = 14
    TYPE_BITFIELD32   = 15
    _hdr_struct = Struct("HH")

    class _int_struct:
        def __init__(self, pattern): # type: (str) -> None
            self._struct = Struct(pattern)
        def pack(self, obj): # type: (int) -> bytes
            return self._struct.pack(int(obj))
        def unpack(self, data, offset=0, length=0): 
            # type: (bytes, int, int) -> int
            return self._struct.unpack_from(data, offset)[0]

    class _str_struct:
        def __init__(self, null=False): # type: (bool) -> None
            self.null = null
        def pack(self, obj): # type: (str) -> bytes
            if sys.version_info.major == 3:
                obj = str(obj).encode()
            else:
                obj = str(obj)
            if self.null:
                return pack("%ds" % (len(obj) + 1), obj)
            else:
                return pack("%ds" % len(obj), obj)
        def unpack(self, data, offset=0, length=0): 
            # type: (bytes, int, int) -> str
            if self.null:
                obj = unpack_from("%ds" % (length - 1), data, offset)[0]
            else:
                obj = unpack_from("%ds" % length, data, offset)[0]
            if sys.version[:1] == '3':
                return obj.decode()
            else:
                return str(obj)

    _bitfield32 = namedtuple("_bitfield", "value selector")
    class _bitfield32_struct():
        _struct = Struct("II")
        @classmethod
        def pack(cls, obj): # type: (NLAttr._bitfield32) -> bytes
            return cls._struct.pack(*obj)
        @classmethod
        def unpack(cls, data, offset=0, length=0): 
            # type: (bytes, int, int) -> NLAttr._bitfield32
            return NLAttr._bitfield32(*cls._struct.unpack_from(data, offset))

    class _ipaddr_struct:
        _struct = Struct("BBBB")
        @classmethod
        def pack(cls, obj): # type: (str) -> bytes
            octets = [int(o) for o in str(obj).strip().split('.')]
            if len(octets) != 4:
                raise Exception("%r is not a valid IP address" % obj)
            return cls._struct.pack(*octets)            
        @classmethod
        def unpack(cls, data, offset=0, length=0): 
            # type: (bytes, int, int) -> str
            return '{}.{}.{}.{}'.format(*cls._struct.unpack_from(data, offset))

    class _macaddr_struct:
        _struct = Struct("BBBBBB")
        @classmethod
        def pack(cls, obj): # type: (str) -> bytes
            octets = [int(o, 16) for o in str(obj).strip().split(':')]
            if len(octets) != 6:
                raise Exception("%r is not a valid MAC address" % obj)
            return cls._struct.pack(*octets)            
        @classmethod
        def unpack(cls, data, offset=0, length=0): 
            # type: (bytes, int, int) -> str
            return '{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}'\
                .format(*cls._struct.unpack_from(data, offset))

    _struct = {
        TYPE_FLAG: _int_struct("B"),
        TYPE_U8: _int_struct("B"),
        TYPE_U16: _int_struct("H"),
        TYPE_U32: _int_struct("I"),
        TYPE_U64: _int_struct("Q"),
        TYPE_S8: _int_struct("b"),
        TYPE_S16: _int_struct("h"),
        TYPE_S32: _int_struct("i"),
        TYPE_S64: _int_struct("q"),
        TYPE_BINARY: None,
        TYPE_STRING: _str_struct(False),
        TYPE_NUL_STRING: _str_struct(True),
        TYPE_NESTED: None,
        TYPE_NESTED_ARRAY: None,
        TYPE_BITFIELD32: _bitfield32_struct(),
    }

    # def __init__(self, type, data): # type: (int, any) -> None
    #     # if type not in self._struct:
    #     #     raise ValueError("unknown type: %d" % type)
    #     self.type = type
    #     self.data = data

    @staticmethod    
    def _align(len, bs=4): # type: (int, int) -> int
        return (len + bs - 1) & ~(bs - 1)

    @property
    def size(self):
        return self._align(len(self))

    def __len__(self):
        return self._hdr_struct.size + len(self._pack_data())

    def _pack_header(self): # type: () -> bytes
        return self._hdr_struct.pack(len(self), self.type)

    def _pack_data(self): # type: () -> bytes
        if self.type in self._struct and self._struct[self.type]:
            return self._struct[self.type].pack(self.data)
        else:
            return self.data

    @property
    def _bytes(self): # type() -> bytes
        data = bytearray(self._pack_header())
        data.extend(self._pack_data())
        data.extend(bytes(b'\x00' * (self.size - len(self))))
        return bytes(data)

    @classmethod
    def _from(cls, data, offset=0): # type: (bytes|bytearray, int) -> NLAttr
        length, type = cls._hdr_struct.unpack_from(data, offset)
        if type in cls._struct and cls._struct[type]:
            data = cls._struct[type].unpack(
                data, offset + cls._hdr_struct.size, 
                length - cls._hdr_struct.size)
        else:
            data = data[offset + cls._hdr_struct.size:offset + length]
        return cls(type, data)

    @classmethod
    def list(cls, data, offset=0): 
        # type: (bytes|bytearray, int) -> list[NLAttr]
        results = []
        while offset < len(data):
            attr = cls._from(data, offset)
            results.append(attr)
            offset += attr.size
        return results

    @classmethod
    def dict(cls, data, offset=0): 
        # type: (bytes|bytearray, int) -> dict[int, any]
        return {
            a.type: a.data for a in cls.list(data, offset)
        }


class NLMessage(object):
    ## include/uapi/linux/netlink.h
    # Types
    TYPE_NOOP     = 0x1 
    TYPE_ERROR    = 0x2 
    TYPE_DONE     = 0x3 
    TYPE_OVERRUN  = 0x4 
    TYPE_MIN      = 0x10
    # Error attrs
    ERR_ATTR_UNUSED = 0
    ERR_ATTR_MSG    = 1
    ERR_ATTR_OFFS   = 2
    ERR_ATTR_COOKIE = 3
    ERR_ATTR_POLICY = 4
    # Flags values
    FLAG_REQUEST       = 0x01 
    FLAG_MULTI         = 0x02 
    FLAG_ACK           = 0x04 
    FLAG_ECHO          = 0x08
    FLAG_DUMP_INTR     = 0x10 # Dump was inconsistent due to sequence change
    FLAG_DUMP_FILTERED	= 0x20 # Dump was filtered as requested
    # Modifiers to GET request
    FLAG_ROOT   = 0x100
    FLAG_MATCH  = 0x200
    FLAG_DUMP   = 0x300
    FLAG_ATOMIC = 0x400
    # Modifiers to NEW request
    FLAG_REPLACE = 0x100   # Override existing
    FLAG_EXCL    = 0x200   # Do not touch, if it exists
    FLAG_CREATE  = 0x400   # Create, if it does not exist
    FLAG_APPEND  = 0x800   # Add to end of list
    ## include/uapi/linux/rtnetlink.h
    # Routing messages
    RTM_BASE         = 16
    RTM_NEWLINK      = 16
    RTM_DELLINK      = 17
    RTM_GETLINK      = 18
    RTM_SETLINK      = 19
    RTM_NEWADDR      = 20
    RTM_DELADDR      = 21
    RTM_GETADDR      = 22
    RTM_NEWROUTE     = 24
    RTM_DELROUTE     = 25
    RTM_GETROUTE     = 26
    RTM_NEWNEIGH     = 28
    RTM_DELNEIGH     = 29
    RTM_GETNEIGH     = 30
    RTM_NEWRULE      = 32
    RTM_DELRULE      = 33
    RTM_GETRULE      = 34
    RTM_NEWQDISC     = 36
    RTM_DELQDISC     = 37
    RTM_GETQDISC     = 38
    RTM_NEWTCLASS    = 40
    RTM_DELTCLASS    = 41
    RTM_GETTCLASS    = 42
    RTM_NEWTFILTER   = 44
    RTM_DELTFILTER   = 45
    RTM_GETTFILTER   = 46
    RTM_NEWACTION    = 48
    RTM_DELACTION    = 49
    RTM_GETACTION    = 50
    RTM_NEWPREFIX    = 52
    RTM_GETMULTICAST = 58
    RTM_GETANYCAST   = 62
    RTM_NEWNEIGHTBL  = 64
    RTM_GETNEIGHTBL  = 66
    RTM_SETNEIGHTBL  = 67
    RTM_NEWNDUSEROPT = 68
    RTM_NEWADDRLABEL = 72
    RTM_DELADDRLABEL = 73
    RTM_GETADDRLABEL = 74
    RTM_GETDCB       = 78
    RTM_SETDCB       = 77
    RT_TABLE_MAIN    = 254
    ## struct nlmsghdr;
    _hdr_struct = Struct("IHHII")

    def __init__(self, type, flags=0, seq=-1, data=None): 
        # type: (int, int, int, bytes) -> None
        self.type = type
        self.flags = flags
        self.seq = seq
        self.pid = 0
        self.data = bytearray(data)

    @staticmethod
    def _align(len, bs=4): # type: (int, int) -> int
        return (len + bs - 1) & ~(bs - 1)

    def __len__(self):
        return self._align(self._hdr_struct.size + len(self.data))

    def __str__(self):
        return ("NLMessage(len=%d, type=%d, flags=0x%04X, seq=%d, pid=%d)" %
            (len(self), self.type, self.flags, self.seq, self.pid))

    @property
    def _bytes_header(self): # type: () -> bytes
        return self._hdr_struct.pack(
            len(self), self.type, self.flags, self.seq, 0)

    @property
    def _bytes(self): # type() -> bytes
        return bytes(self._bytes_header + self.data)

    @classmethod
    def _from(cls, data, offset=0): # type: (bytes, int) -> NLMessage
        length, type, flags, seq, _ = cls._hdr_struct.unpack_from(
            data, offset)
        payload = data[offset + cls._hdr_struct.size:offset + length]
        return cls(type, flags, seq, payload)
        
class NLConn(object):
    ## include/linux/if_ether.h
    ETH_P_IP = 0x0800
    ## include/uapi/linux/netlink.h
    NETLINK_ROUTE   = 0 # ip/tc
    NETLINK_GENERIC = 16 # ethtool/devlink

    def __init__(self, service=0, groups=0, bufsize=16384):
        # type: (int, int, int, bool) -> None
        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, service)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bufsize)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bufsize)
        self.socket.bind((0, groups))
        self.bufsize = bufsize
        self.pid, self.groups = self.socket.getsockname()
        self._seq = 0

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.socket.close()

    def sendmsg(self, msg): # type: (NLMessage) -> None
        if isinstance(msg, NLMessage):
            if msg.seq == -1: 
                msg.seq = self.seq
            msg.pid = self.pid
            msg = msg._bytes
        self.socket.send(msg)

    def recvmsgs(self): # type: () -> list[NLMessage]
        data = self.socket.recv(int(self.bufsize / 2))
        msgs = []
        offset = 0
        while offset < len(data):
            msg = NLMessage._from(data, offset)
            if msg.type == NLMessage.TYPE_ERROR:
                errno = -unpack_from("i", msg.data)[0]
                if errno != 0:
                    err = OSError("Netlink error: %s (%d)" % 
                        (os.strerror(errno), errno))
                    err.errno = errno
                    raise err
            msgs.append(msg)
            offset += len(msg)
        return msgs

    def send(self, msg): # type: (NLMessage) -> list[NLMessage]
        self.sendmsg(msg)
        done = False
        msgs = []
        while not done:
            for m in self.recvmsgs():
                if m.type in [NLMessage.TYPE_DONE, NLMessage.TYPE_ERROR]:
                    done = True
                    break
                msgs.append(m)
        return msgs

    @property
    def seq(self):
        self._seq += 1
        return self._seq

class RNLConn(NLConn):
    def __init__(self, groups=0, bufsize=16384):
        super(RNLConn, self).__init__(NLConn.NETLINK_ROUTE, groups, bufsize)

class GNLAttr(NLAttr):
    TYPE_FAMILY_ID    = 1
    TYPE_FAMILY_NAME  = 2
    TYPE_VERSION      = 3
    TYPE_HDRSIZE      = 4
    TYPE_MAXATTR      = 5
    TYPE_OPS          = 6
    TYPE_MCAST_GROUPS = 7
    TYPE_POLICY       = 8
    TYPE_OP_POLICY    = 9
    TYPE_OP           = 10

    _struct = {
        TYPE_FAMILY_ID: NLAttr._int_struct("H"),
        TYPE_FAMILY_NAME: NLAttr._str_struct(True),
        TYPE_VERSION: NLAttr._int_struct("I"),
        TYPE_HDRSIZE: NLAttr._int_struct("I"),
        TYPE_MAXATTR: NLAttr._int_struct("I"),
    }

class GNLOps(NLAttr):
    _struct = {}

class GNLOAttr(NLAttr):
    TYPE_OP_ID    = 1
    TYPE_OP_FLAGS = 2

    _struct = {
        TYPE_OP_ID: NLAttr._int_struct("I"),
        TYPE_OP_FLAGS: NLAttr._int_struct("I")
    }

class GNLConn(NLConn):
    ## include/uapi/linux/genetlink.h
    GENL_ADMIN_PERM     = 0x01
    GENL_CMD_CAP_DO     = 0x02
    GENL_CMD_CAP_DUMP   = 0x04
    GENL_CMD_CAP_HASPOL = 0x08
    GENL_UNS_ADMIN_PERM = 0x10
    GENL_ID_CTRL      = NLMessage.TYPE_MIN
    GENL_ID_VFS_DQUOT = (NLMessage.TYPE_MIN + 1)
    GENL_ID_PMCRAID   = (NLMessage.TYPE_MIN + 2)
    # /* must be last reserved + 1 */
    GENL_START_ALLOC  = (NLMessage.TYPE_MIN + 3)
    CTRL_CMD_UNSPEC       = 0
    CTRL_CMD_NEWFAMILY    = 1
    CTRL_CMD_DELFAMILY    = 2
    CTRL_CMD_GETFAMILY    = 3
    CTRL_CMD_NEWOPS       = 4
    CTRL_CMD_DELOPS       = 5
    CTRL_CMD_GETOPS       = 6
    CTRL_CMD_NEWMCAST_GRP = 7
    CTRL_CMD_DELMCAST_GRP = 8
    CTRL_CMD_GETMCAST_GRP = 9 # /* unused */
    CTRL_CMD_GETPOLICY    = 10

    class Genlmsghdr(StructTempl, namedtuple("Genlmsghdr", 
            "cmd version reserved")):
        _struct = "BBH"

    def __init__(self, groups=0, bufsize=16384):
        # type: (int, int) -> None
        super(GNLConn, self).__init__(NLConn.NETLINK_GENERIC, groups, bufsize)

    def family(self, name):
        # type: (str) -> tuple[int, int, list[int]]
        # get family info: id, version, cmds
        try:
            msgs = self.send(NLMessage(
                type=self.GENL_ID_CTRL,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_ACK,
                data=GNLConn.Genlmsghdr(self.CTRL_CMD_GETFAMILY, 1, 0)._bytes +
                    GNLAttr(GNLAttr.TYPE_FAMILY_NAME, name)._bytes
            ))
        except:
            raise Exception("kernel does not support %r" % name)
        for m in msgs:
            if m.type != self.GENL_ID_CTRL:
                raise Exception("not a controller message: " + str(m))
            msg = GNLConn.Genlmsghdr._from(m.data)
            name = None
            pos = msg._size
            if msg.cmd != self.CTRL_CMD_NEWFAMILY:
                continue
            attrs = GNLAttr.dict(m.data, pos)
            cmds = []
            for attr in GNLOps.list(
                    attrs.get(GNLAttr.TYPE_OPS, b'\x04\x00\x00\x00')):
                cmds.append(GNLOAttr.dict(attr.data)[GNLOAttr.TYPE_OP_ID])
            return (
                attrs.get(GNLAttr.TYPE_FAMILY_ID, None),
                attrs.get(GNLAttr.TYPE_VERSION, None),
                cmds
            )
        raise Exception("netlink communication error")

class IFLAttr(NLAttr):
    ## include/uapi/linux/if_link.h
    TYPE_ADDRESS   = 1
    TYPE_OPERSTATE = 16

    class _state_struct:
        ## iproute2/ip/ipaddress.c
        STATES = [
            'UNKNOWN', 'NOTPRESENT', 'DOWN', 
            'LOWERLAYERDOWN', 'TESTING', 'DORMANT', 'UP'
            ]
        @classmethod
        def pack(cls, obj): # type: (str) -> bytes
            return pack("B", cls.STATES.index(obj))
        @classmethod
        def unpack(cls, data, offset=0, length=0): 
            # type (bytes, int, int) -> str
            index = unpack_from("B", data, offset)[0]
            return cls.STATES[index]

    _struct = {
        TYPE_ADDRESS: NLAttr._ipaddr_struct(),
        TYPE_OPERSTATE: _state_struct()
    }

    def __str__(self):
        return "IFLAttr(type=%d, data=%r)" % (self.type, self.data)


class IPtool(object):
    ## struct ifaddrmsg;
    class IFAddrmsg(StructTempl, namedtuple("IFAddrmsg", 
            "family prefixlen flags scope index")):
        _struct = "BBBBI"

    ## struct ifinfomsg;
    class IFInfomsg(StructTempl, namedtuple("IFInfomsg", 
        "family type index flags mask")):
        _struct = "BxHiII"

    def __init__(self, ifname): # type: (str) -> None
        self.ifname = ifname
        self.ifindex = if_nametoindex(ifname)

    def addrs(self): # type: () -> list[str]
        addrs = []
        with RNLConn() as conn:
            msgs = conn.send(NLMessage(
                type=NLMessage.RTM_GETADDR,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_DUMP,
                data=self.IFAddrmsg(socket.AF_INET, 0, 0, 0, 0)._bytes
            ))
            for m in msgs:
                msg = self.IFAddrmsg._from(m.data)
                if msg.index != self.ifindex:
                    continue
                pos = msg._size
                while pos < len(m.data):
                    attr = IFLAttr._from(m.data, pos) 
                    pos += attr.size
                    if attr.type == IFLAttr.TYPE_ADDRESS:
                        addrs.append(attr.data)
                        break
        return addrs

    def link_state(self): # type () -> str
        with RNLConn() as conn:
            msgs = conn.send(NLMessage(
                type=NLMessage.RTM_GETLINK,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_DUMP,
                data=self.IFInfomsg(socket.AF_UNSPEC, 0, 0, 0, 0)._bytes
            ))
            for m in msgs:
                msg = self.IFInfomsg._from(m.data)
                if msg.index != self.ifindex:
                    continue
                pos = msg._size
                while pos < len(m.data):
                    attr = IFLAttr._from(m.data, pos) 
                    pos += attr.size
                    if attr.type == IFLAttr.TYPE_OPERSTATE:
                        return attr.data


class TCAttr(NLAttr):
    ## include/uapi/linux/rtnetlink.h
    TYPE_KIND    = 1
    TYPE_OPTIONS = 2

    _struct = {
        TYPE_KIND: NLAttr._str_struct(True),
        TYPE_OPTIONS: None
    }

    def __str__(self):
        return "TCAttr(type=%d, data=%r)" % (self.type, self.data)


class TCMQAttr(NLAttr):
    ## include/uapi/linux/rtnetlink.h
    TYPE_MODE   = 1
    TYPE_SHAPER = 2
    MODE_DCB     = 0
    MODE_CHANNEL = 1
    SHAPER_DCB     = 0
    SHAPER_BW_RATE = 1
    TYPE_MINRATE = 3
    TYPE_MAXRATE = 4   

    _struct = {
        TYPE_MODE: NLAttr._int_struct("H"),
        TYPE_SHAPER: NLAttr._int_struct("H"),
        TYPE_MINRATE: NLAttr._int_struct("Q"),
        TYPE_MAXRATE: NLAttr._int_struct("Q")
    }

    def __str__(self):
        return "TCMQAttr(type=%d, data=%r)" % (self.type, self.data)

class TCMQNestAttr(NLAttr):
    TYPE_MINRATE = 3
    TYPE_MAXRATE = 4
    
    class _nest_array:
        _item_type = 0
        def __init__(self, item_type): # type: (str) -> None
            self._item_type = item_type
        @classmethod
        def pack(cls, obj):
            data = bytearray([]) # changed
            for i in range(len(obj)):
                data = data + obj[i]._bytes
            return data
        @classmethod
        def unpack(cls, data, offset=0, length=0): 
            results = []
            item = TCMQAttr(cls._item_type, 0)
            while offset < len(data):
                attr =item._from(data, offset)
                results.append(attr)
                offset += attr.size
            return results
        
    _struct = {
        TYPE_MINRATE: _nest_array(TYPE_MINRATE),
        TYPE_MAXRATE: _nest_array(TYPE_MAXRATE),
    }

    def __str__(self):
        return "TCMQNestAttr(type=%d, data=%r)" % (self.type, self.data)

class TCFLAttr(NLAttr):
    ## /include/uapi/linux/pkt_cls.h
    TYPE_CLASSID           = 1
    TYPE_INDEV             = 2
    TYPE_ACT               = 3
    TYPE_KEY_ETH_DST       = 4 # /* u8[6] */
    TYPE_KEY_ETH_DST_MASK  = 5 # /* u8[6] */
    TYPE_KEY_ETH_SRC       = 6 # /* u8[6] */
    TYPE_KEY_ETH_SRC_MASK  = 7 # /* u8[6] */
    TYPE_KEY_ETH_TYPE      = 8 # /* be16 */
    TYPE_KEY_IP_PROTO      = 9 # /* u8 */
    TYPE_KEY_IPV4_SRC      = 10 # /* be32 */
    TYPE_KEY_IPV4_SRC_MASK = 11 # /* be32 */
    TYPE_KEY_IPV4_DST      = 12 # /* be32 */
    TYPE_KEY_IPV4_DST_MASK = 13 # /* be32 */
    TYPE_KEY_TCP_SRC       = 18 # /* be16 */
    TYPE_KEY_TCP_DST       = 19 # /* be16 */
    TYPE_KEY_UDP_SRC       = 20 # /* be16 */
    TYPE_KEY_UDP_DST       = 21 # /* be16 */
    TYPE_FLAGS             = 22
    TYPE_MAX               = 91
    ACT_KIND    = 1
    ACT_OPTIONS = 2
    ACT_INDEX   = 3
    ACT_STATS   = 4
    ACT_PAD     = 5
    ACT_COOKIE  = 6
    ACT_OK         = 0
    ACT_RECLASSIFY = 1
    ACT_SHOT       = 2
    ACT_PIPE       = 3
    ACT_STOLEN     = 4
    ACT_QUEUED     = 5
    ACT_REPEAT     = 6
    ACT_REDIRECT   = 7
    ACT_TRAP		  = 8
    ACT_MAX_PRIO = 32
    ACT_BIND   = 1
    ACT_NOBIND = 0
    ACT_UNBIND   = 1
    ACT_NOUNBIND = 0
    ACT_REPLACE = 1
    ACT_NOREPLACE = 0
    ACT_ID_SKBEDIT = 11
    ## include/uapi/linux/pkt_cls.h
    # TCA flags
    FLAGS_SKIP_SW = (1 << 1)

    class _ipproto_struct:
        ## /include/uapi/linux/in.h
        IPPROTO_TCP = 6
        IPPROTO_UDP = 17
        strings = {'tcp': IPPROTO_TCP, 'udp': IPPROTO_UDP}
        struct = Struct("B")

        @classmethod
        def pack(cls, obj): # type: (str) -> bytes
            obj = str(obj).strip().lower()
            if obj not in cls.strings:
                raise Exception("unknown ip proto type %r" % obj)
            return cls.struct.pack(cls.strings[obj])

        @classmethod
        def unpack(cls, data, offset=0, length=0): 
            # type: (bytes, int, int) -> str
            data = cls.struct.unpack_from(data, offset)[0]
            for n, v in cls.strings.items():
                if data == v:
                    return n
            raise Exception("unknown ip proto id %d" % data)

    _struct = {
        TYPE_CLASSID: NLAttr._int_struct("I"),
        TYPE_KEY_ETH_TYPE: NLAttr._int_struct("!H"),
        TYPE_KEY_IP_PROTO: _ipproto_struct(),
        TYPE_KEY_ETH_DST: NLAttr._macaddr_struct(),
        TYPE_KEY_ETH_DST_MASK: NLAttr._macaddr_struct(),
        TYPE_KEY_ETH_SRC: NLAttr._macaddr_struct(),
        TYPE_KEY_ETH_SRC_MASK: NLAttr._macaddr_struct(),
        TYPE_KEY_IPV4_SRC: NLAttr._ipaddr_struct(),
        TYPE_KEY_IPV4_SRC_MASK: NLAttr._ipaddr_struct(),
        TYPE_KEY_IPV4_DST: NLAttr._ipaddr_struct(),
        TYPE_KEY_IPV4_DST_MASK: NLAttr._ipaddr_struct(),
        TYPE_KEY_TCP_SRC: NLAttr._int_struct("!H"),
        TYPE_KEY_TCP_DST: NLAttr._int_struct("!H"),
        TYPE_KEY_UDP_SRC: NLAttr._int_struct("!H"),
        TYPE_KEY_UDP_DST: NLAttr._int_struct("!H"),
        TYPE_FLAGS: NLAttr._int_struct("I")
    }

    def __str__(self):
        return "TCFLAttr(type=%d, data=%r)" % (self.type, self.data)


class TCSKBAttr(NLAttr):
    TYPE_TM            = 1
    TYPE_PARMS         = 2
    TYPE_PRIORITY      = 3
    TYPE_QUEUE_MAPPING = 4
    TYPE_MARK          = 5
    TYPE_PAD           = 6
    TYPE_PTYPE         = 7
    TYPE_MASK          = 8
    TYPE_FLAGS         = 9
    ACT_PIPE = 3    
    _params = namedtuple("_skb_params", "index capab action refcnt bindcnt")

    class _skb_params_struct(object):
        _struct = Struct("IIiii")
        @classmethod
        def pack(cls, obj): # type: (TCSKBAttr._params) -> bytes
            return cls._struct.pack(*obj)
        @classmethod
        def unpack(cls, data, offset=0, length=0): 
            # type: (bytes, int, int) -> TCSKBAttr._params
            return TCSKBAttr._params(*cls._struct.unpack_from(data, offset))

    _struct = {
        TYPE_PARMS: _skb_params_struct(),
        TYPE_PRIORITY: NLAttr._int_struct("I"),
        TYPE_QUEUE_MAPPING: NLAttr._int_struct("H")
    }

    def __str__(self):
        return "TCSKBAttr(type=%d, data=%r)" % (self.type, self.data)


class TCAction(NLAttr, namedtuple("TCAction", "order data")):
    _struct = {}    


class TCtool(object):
    ## include/uapi/linux/pkt_sched.h
    # TC (qdisc mqprio) nested attrs
    TCA_MQPRIO_MODE   = 1
    TCA_MQPRIO_SHAPER = 2
    TC_QOPT_MAX_QUEUE = 16
    # TC Handles
    TC_H_UNSPEC    = 0
    TC_H_ROOT    = 0xFFFFFFFF
    TC_H_INGRESS = 0xFFFFFFF1
    TC_H_CLSACT  = TC_H_INGRESS
    TC_H_MIN_PRIORITY = 0xFFE0
    TC_H_MAX_PRIORITY = TC_H_MIN_PRIORITY + TC_QOPT_MAX_QUEUE - 1
    TC_H_MIN_INGRESS  = 0xFFF2
    TC_H_MIN_EGRESS   = 0xFFF3
    TC_H_MAJ_MASK = 0xFFFF0000
    TC_H_MIN_MASK = 0x0000FFFF

    @classmethod
    def _tc_h_maj(cls, h): # type: (int) -> int
        #define TC_H_MAJ(h) ((h)&TC_H_MAJ_MASK)
        return h & cls.TC_H_MAJ_MASK

    @classmethod
    def _tc_h_min(cls, h): # type: (int) -> int
        #define TC_H_MIN(h) ((h)&TC_H_MIN_MASK)
        return h & cls.TC_H_MIN_MASK

    @classmethod
    def _tc_h_make(cls, maj, min): # type: (int, int) -> int
        #define TC_H_MAKE(maj,min) (((maj)&TC_H_MAJ_MASK)|((min)&TC_H_MIN_MASK))
        return cls._tc_h_maj(maj) | cls._tc_h_min(min)

    @staticmethod
    def _from_cidr(addr):
        # type: (str) -> tuple[str, str]
        addr, mask = addr.split('/')
        mask = int(mask)
        if mask > 32:
            raise Exception("ip address mask must be <= 32")
        mask = '{}.{}.{}.{}'.format(
            *unpack('4B', pack('>I', sum([1 << (31 - i) for i in range(mask)])))
        )
        return addr, mask

    @staticmethod
    def _to_cidr(addr, mask):
        # type: (str, str) -> str
        octets = [int(o) for o in str(mask).strip().split('.')]
        mask = bin(unpack('>I', pack('4B', *octets))[0]).count('1')
        return '/'.join(addr, str(mask))

    class TCmsg(StructTempl, namedtuple("TCmsg", 
            "family index handle parent info")):
        _struct = "B3xiIII"

    Clsact = namedtuple("Qdisc", "parent kind")
    Qdisc = namedtuple("Qdisc", 
        "parent kind num_tc map hw count offset mode shaper min_rate max_rate")
    Filter = namedtuple("Filter", 
        "prio proto src_mac src_addr src_port"
        " dst_mac dst_addr dst_port queue tc action priority")

    def __init__(self, ifname, log=None): # type: (str, any) -> None
        self.ifname = ifname
        self.ifindex = if_nametoindex(ifname)
        self.log = log

    def _log(self, *args): # type: (...) -> None
        if self.log:
            for a in args:
                self.log.write(str(a) + '\n')

    def qdisc_list(self):
        # type: () -> list[Qdisc|Clsact]
        with RNLConn() as conn:
            msgs = conn.send(NLMessage(
                type=NLMessage.RTM_GETQDISC,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_DUMP,
                data=self.TCmsg(socket.AF_UNSPEC, self.ifindex, 0, 0, 0)._bytes
            ))
            results = []
            for m in msgs:
                if m.type != NLMessage.RTM_NEWQDISC:
                    continue
                msg = self.TCmsg._from(m.data)
                if msg.index != self.ifindex:
                    continue
                kind = ''
                for attr in TCAttr.list(m.data, msg._size):
                    if attr.type == TCAttr.TYPE_KIND:
                        kind = attr.data
                        if kind not in ['mqprio', 'clsact']:
                            break
                    elif attr.type == TCAttr.TYPE_OPTIONS:
                        if kind == 'mqprio':
                            num_tc = unpack_from("B", attr.data)[0]
                            pmap = unpack_from("16B", attr.data, 1)
                            hw = unpack_from("B", attr.data, 17)[0]
                            count = unpack_from("16H", attr.data, 18)
                            offset = unpack_from("16H", attr.data, 50)
                            attrs = TCMQAttr.dict(attr.data, 84)
                            mode = attrs.get(TCMQAttr.TYPE_MODE, None)
                            shaper = attrs.get(TCMQAttr.TYPE_SHAPER, None)
                            attrs_nest = TCMQNestAttr.dict(attr.data, 100)
                            min_rate = attrs_nest.get(TCMQNestAttr.TYPE_MINRATE, None)
                            max_rate = attrs_nest.get(TCMQNestAttr.TYPE_MAXRATE, None)
                            results.append(self.Qdisc(
                                msg.parent, kind, num_tc, pmap, hw, 
                                count, offset, mode, shaper, min_rate, max_rate
                            ))
                            break
                        elif kind == 'clsact':
                            results.append(self.Clsact(msg.parent, kind))
                            break
            return results

    def qdisc_add(self, parent=None, kind=None, 
            pmap=None, count=None, offset=None, min_rate=None, max_rate=None):
        # type: (int, str, list[int], list[int], list[int], list[int], list[int]) -> None
        with RNLConn() as conn:
            handle = 0
            if parent == self.TC_H_CLSACT:
                handle = self._tc_h_make(parent, 0)
            msg = NLMessage(
                type=NLMessage.RTM_NEWQDISC,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_ACK | 
                    NLMessage.FLAG_CREATE | NLMessage.FLAG_EXCL,
                data=self.TCmsg(
                    socket.AF_UNSPEC, self.ifindex, handle, parent, 0)._bytes
            )
            msg.data = msg.data + TCAttr(TCAttr.TYPE_KIND, kind)._bytes
            if kind == 'mqprio':
                # normalize maps and limit to 16 TCs
                max_tc = self.TC_QOPT_MAX_QUEUE
                pmap = pmap[:max_tc]
                count = count[:len(pmap)]
                offset = offset[:len(pmap)]
                if min_rate is not None or max_rate is not None:
                    minrate = array('Q', [0] * 16)
                    if min_rate is not None:
                        for i in range(len(min_rate)):
                            pnum = pack("Q", min_rate[i] if min_rate[i] is not None else 0)
                            num = unpack("Q", pnum)[0] * 125000
                            minrate[i] = num
                    maxrate = array('Q', [0] * 16)
                    if max_rate is not None:
                        for i in range(len(max_rate)):
                            pnum = pack("Q", max_rate[i] if max_rate[i] is not None else 0)
                            num = unpack("Q", pnum)[0] * 125000
                            maxrate[i] = num
                    # nested attrs
                    min_rates = [TCMQAttr(TCMQAttr.TYPE_MINRATE, minrate[i]) for i in range(16)]
                    max_rates = [TCMQAttr(TCMQAttr.TYPE_MAXRATE, maxrate[i]) for i in range(16)]
                    msg.data = msg.data + TCAttr(
                        TCAttr.TYPE_OPTIONS, 
                        pack("B", len(pmap)) + _pack_list(pmap, 'B', max_tc) 
                        + pack("B", 1) + _pack_list(count, 'H', max_tc) 
                        + _pack_list(offset, 'H', max_tc)
                        + b'\x00' * 2 # DWORD alignment padding
                        + TCMQAttr(TCMQAttr.TYPE_MODE, TCMQAttr.MODE_CHANNEL)._bytes
                        + TCMQAttr(TCMQAttr.TYPE_SHAPER, TCMQAttr.SHAPER_BW_RATE)._bytes
                        + TCMQNestAttr(TCMQNestAttr.TYPE_MINRATE, min_rates)._bytes
                        + TCMQNestAttr(TCMQNestAttr.TYPE_MAXRATE, max_rates)._bytes
                    )._bytes
                else:
                    # nested attrs
                    msg.data = msg.data + TCAttr(
                        TCAttr.TYPE_OPTIONS, 
                        pack("B", len(pmap)) + _pack_list(pmap, 'B', max_tc) 
                        + pack("B", 1) + _pack_list(count, 'H', max_tc) 
                        + _pack_list(offset, 'H', max_tc)
                        + b'\x00' * 2 # DWORD alignment padding
                        + TCMQAttr(TCMQAttr.TYPE_MODE, TCMQAttr.MODE_CHANNEL)._bytes
                    )._bytes
            conn.send(msg)
            if self.log:
                if parent == self.TC_H_ROOT and kind == "mqprio":
                    self._log(
                        "tc qdisc add dev %s root mqprio" \
                        " num_tc %d map %s queues %s hw 1 mode channel" %
                        (self.ifname, len(pmap), 
                            ' '.join([str(p) for p in pmap]), 
                            ' '.join([str(count[i])+'@'+str(offset[i]) \
                                for i in range(len(pmap))]))
                    )
                elif parent == self.TC_H_CLSACT and kind == "clsact":
                    self._log("tc qdisc add dev %s clsact" % (self.ifname))

    def qdisc_del(self, parent=None, kind=None):
        # type: (int, str) -> None
        with RNLConn() as conn:
            handle = 0
            if parent == self.TC_H_CLSACT:
                handle = self._tc_h_make(parent, 0)
            msg = NLMessage(
                type=NLMessage.RTM_DELQDISC,
                flags=NLMessage.FLAG_REQUEST,
                data=self.TCmsg(
                    socket.AF_UNSPEC, self.ifindex, handle, parent, 0)._bytes
            )
            msg.data = msg.data + TCAttr(TCAttr.TYPE_KIND, kind)._bytes
            conn.sendmsg(msg)
            # send simulated commands to the log
            if parent == self.TC_H_ROOT:
                self._log("tc qdisc del dev %s root %s" % (self.ifname, kind))
            elif parent == self.TC_H_CLSACT and kind == "clsact":
                self._log("tc qdisc del dev %s clsact" % (self.ifname))

    def _filter_list(self, parent):
        # type: (int) -> list[Filter]
        with RNLConn() as conn:
            msgs = conn.send(NLMessage(
                type=NLMessage.RTM_GETTFILTER,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_DUMP,
                data=self.TCmsg(
                    socket.AF_UNSPEC, self.ifindex, 0, parent, 0)._bytes
            ))
            results = []
            for m in msgs:
                if m.type != NLMessage.RTM_NEWTFILTER:
                    continue
                msg = self.TCmsg._from(m.data)
                if msg.index != self.ifindex:
                    continue
                if self._tc_h_min(msg.info) != socket.htons(RNLConn.ETH_P_IP):
                    continue
                prio = self._tc_h_maj(msg.info) >> 16 
                kind = ''
                for attr in TCAttr.list(m.data, msg._size):
                    if attr.type == TCAttr.TYPE_KIND:
                        kind = attr.data
                    elif attr.type == TCAttr.TYPE_OPTIONS and kind == 'flower':
                        queue = None
                        tc = None
                        action = None
                        priority = None
                        attrs = TCFLAttr.dict(attr.data)
                        classid = attrs.get(TCFLAttr.TYPE_CLASSID, None)
                        if classid is not None:
                            hmin = self._tc_h_min(classid)
                            if hmin < self.TC_H_MIN_PRIORITY:
                                queue = hmin - 1
                            elif hmin >= self.TC_H_MIN_PRIORITY and \
                                    hmin <= self.TC_H_MAX_PRIORITY:
                                tc = hmin - self.TC_H_MIN_PRIORITY
                        proto = attrs.get(TCFLAttr.TYPE_KEY_IP_PROTO, None)
                        dst_mac = attrs.get(TCFLAttr.TYPE_KEY_ETH_DST, None)
                        dst_addr = attrs.get(TCFLAttr.TYPE_KEY_IPV4_DST, None)
                        src_mac = attrs.get(TCFLAttr.TYPE_KEY_ETH_SRC, None)
                        src_addr = attrs.get(TCFLAttr.TYPE_KEY_IPV4_SRC, None)
                        if proto == 'tcp':
                            dst_port = attrs.get(
                                TCFLAttr.TYPE_KEY_TCP_DST, None)
                            src_port = attrs.get(
                                TCFLAttr.TYPE_KEY_TCP_SRC, None)
                        elif proto == 'udp':
                            dst_port = attrs.get(
                                TCFLAttr.TYPE_KEY_UDP_DST, None)
                            src_port = attrs.get(
                                TCFLAttr.TYPE_KEY_UDP_SRC, None)
                        else:
                            dst_port = None
                            src_port = None
                        if TCFLAttr.TYPE_ACT in attrs:
                            actions = TCAction.dict(attrs[TCFLAttr.TYPE_ACT])
                            actions = TCAttr.dict(actions[1])
                            if actions[TCAttr.TYPE_KIND] == "skbedit":
                                action = 'skbedit'
                                options = TCSKBAttr.dict(
                                    actions[TCAttr.TYPE_OPTIONS])
                                priority = options[TCSKBAttr.TYPE_PRIORITY]
                        results.append(self.Filter(
                            prio, proto, src_mac, src_addr, src_port, 
                            dst_mac, dst_addr, dst_port, queue, 
                            tc, action, priority
                        ))
                        break
            return results

    def filter_list(self):
        # type: () -> dict[str, list[Filter]]
        return {
            'ingress': self._filter_list(
                self._tc_h_make(self.TC_H_CLSACT, self.TC_H_MIN_INGRESS)
            ),
            'egress': self._filter_list(
                self._tc_h_make(self.TC_H_CLSACT, self.TC_H_MIN_EGRESS)
            )
        }

    def filter_add(self, direction='ingress', prio=1, proto='tcp', 
            src_mac=None, src_addr=None, src_port=None, 
            dst_mac=None, dst_addr=None, dst_port=None, 
            queue=None, tc=None, action=None, priority=None):
        # type: (str, int, str, str, str, int, str, str, int, int, int, str, int) -> None
        with RNLConn() as conn:
            if proto.lower() not in ['tcp', 'udp']:
                raise Exception('invalid ip protocol %r', proto)
            if direction == 'ingress':
                parent = self._tc_h_make(
                    self.TC_H_CLSACT, self.TC_H_MIN_INGRESS)
            elif direction == 'egress':
                parent = self._tc_h_make(
                    self.TC_H_CLSACT, self.TC_H_MIN_EGRESS)
            else:
                raise Exception("invalid filter direction %r" % direction)
            options = []
            options.append(TCFLAttr(TCFLAttr.TYPE_KEY_IP_PROTO, proto.lower()))
            if src_mac is not None:
                mask = "ff:ff:ff:ff:ff:ff"
                options.append(TCFLAttr(TCFLAttr.TYPE_KEY_ETH_SRC, src_mac))
                options.append(TCFLAttr(TCFLAttr.TYPE_KEY_ETH_SRC_MASK, mask))
            if src_addr is not None:
                addr, mask = self._from_cidr(src_addr)
                options.append(TCFLAttr(TCFLAttr.TYPE_KEY_IPV4_SRC, addr))
                options.append(TCFLAttr(TCFLAttr.TYPE_KEY_IPV4_SRC_MASK, mask))
            if dst_mac is not None:
                mask = "ff:ff:ff:ff:ff:ff"
                options.append(TCFLAttr(TCFLAttr.TYPE_KEY_ETH_DST, dst_mac))
                options.append(TCFLAttr(TCFLAttr.TYPE_KEY_ETH_DST_MASK, mask))
            if dst_addr is not None:
                addr, mask = self._from_cidr(dst_addr)
                options.append(TCFLAttr(TCFLAttr.TYPE_KEY_IPV4_DST, addr))
                options.append(TCFLAttr(TCFLAttr.TYPE_KEY_IPV4_DST_MASK, mask))
            if proto.lower() == 'tcp':
                if src_port is not None:
                    options.append(
                        TCFLAttr(TCFLAttr.TYPE_KEY_TCP_SRC, src_port))
                if dst_port is not None:
                    options.append(
                        TCFLAttr(TCFLAttr.TYPE_KEY_TCP_DST, dst_port))
            elif proto.lower() == 'udp':
                if src_port is not None:
                    options.append(
                        TCFLAttr(TCFLAttr.TYPE_KEY_UDP_SRC, src_port))
                if dst_port is not None:
                    options.append(
                        TCFLAttr(TCFLAttr.TYPE_KEY_UDP_DST, dst_port))
            flags = 0
            if direction == 'ingress' and queue is not None:
                options.append(TCFLAttr(TCFLAttr.TYPE_CLASSID, 
                    self._tc_h_make(self.TC_H_ROOT, queue + 1)
                ))
                flags = flags | TCFLAttr.FLAGS_SKIP_SW
            elif direction == 'ingress' and tc is not None:
                options.append(TCFLAttr(TCFLAttr.TYPE_CLASSID, 
                    self._tc_h_make(parent, tc + self.TC_H_MIN_PRIORITY)
                ))
                flags = flags | TCFLAttr.FLAGS_SKIP_SW
            elif direction == 'egress' and action is not None:
                options.append(TCFLAttr(TCFLAttr.TYPE_ACT, TCAction(1, 
                    TCAttr(TCAttr.TYPE_KIND, action)._bytes + 
                    TCAttr(TCAttr.TYPE_OPTIONS, 
                        TCSKBAttr(TCSKBAttr.TYPE_PRIORITY, priority)._bytes + 
                        TCSKBAttr(TCSKBAttr.TYPE_PARMS, 
                            TCSKBAttr._params(0, 0, TCSKBAttr.ACT_PIPE, 0, 0)
                        )._bytes
                    )._bytes
                )._bytes))
            options.append(TCFLAttr(TCFLAttr.TYPE_FLAGS, flags))
            options.append(TCFLAttr(TCFLAttr.TYPE_KEY_ETH_TYPE, NLConn.ETH_P_IP))
            data = bytearray()
            for a in options:
                data.extend(a._bytes)
            msg = NLMessage(
                type=NLMessage.RTM_NEWTFILTER,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_ACK | 
                    NLMessage.FLAG_EXCL | NLMessage.FLAG_CREATE, 
                data=self.TCmsg(
                        socket.AF_UNSPEC, self.ifindex, 0, parent, 
                        self._tc_h_make(prio << 16, 
                        socket.htons(NLConn.ETH_P_IP))
                    )._bytes +
                    TCAttr(TCAttr.TYPE_KIND, 'flower')._bytes +
                    TCAttr(TCAttr.TYPE_OPTIONS, data)._bytes
            )
            conn.send(msg)
            time.sleep(0.0001)
            if self.log:
                # send simulated commands to the log
                params = [direction, 'prio', str(prio), 'protocol', 'ip', 
                    'flower', 'ip_proto', proto]
                if src_mac is not None:
                    params.extend(['src_mac', src_mac])
                if src_addr is not None:
                    params.extend(['src_ip', src_addr])
                if src_port is not None:
                    params.extend(['src_port', str(src_port)])
                if dst_mac is not None:
                    params.extend(['dst_mac', dst_mac])
                if dst_addr is not None:
                    params.extend(['dst_ip', dst_addr])
                if dst_port is not None:
                    params.extend(['dst_port', str(dst_port)])
                if queue is not None:
                    params.extend(['skip_sw', 'classid', 
                        "FFFF:{:04x}".format(queue + 1)])
                elif tc is not None:
                    params.extend(['skip_sw', 'hw_tc', str(tc)])
                else:
                    if action is not None:
                        params.extend(['action', action, 
                            'priority', str(priority)])
                self._log("tc filter add dev %s %s" % 
                        (self.ifname, ' '.join(params)))

    def filter_del(self, direction='ingress'):
        # type: (str) -> None
        with RNLConn() as conn:
            if direction == 'ingress':
                parent = self._tc_h_make(
                    self.TC_H_CLSACT, self.TC_H_MIN_INGRESS)
            elif direction == 'egress':
                parent = self._tc_h_make(
                    self.TC_H_CLSACT, self.TC_H_MIN_EGRESS)
            else:
                raise Exception("invalid filter direction %r" % direction)
            msg = NLMessage(
                type=NLMessage.RTM_DELTFILTER,
                flags=NLMessage.FLAG_REQUEST,
                data=self.TCmsg(
                    socket.AF_UNSPEC, self.ifindex, 0, parent, 0)._bytes
            )
            conn.sendmsg(msg)
            self._log("tc filter del dev %s %s" % (self.ifname, direction))


class DLAttr(NLAttr):
    ## linux/include/net/devlink.h
    TYPE_BUS_NAME             = 1 # /* string */
    TYPE_DEV_NAME             = 2 # /* string */
    TYPE_PARAM                = 80 # /* nested */
    TYPE_PARAM_NAME           = 81 # /* string */
    TYPE_PARAM_GENERIC        = 82 # /* flag */
    TYPE_PARAM_TYPE           = 83 # /* u8 */
    TYPE_PARAM_VALUES_LIST    = 84 # /* nested */
    TYPE_PARAM_VALUE          = 85 # /* nested */
    TYPE_PARAM_VALUE_DATA     = 86 # /* dynamic */
    TYPE_PARAM_VALUE_CMODE    = 87 # /* u8 */
    TYPE_INFO_DRIVER_NAME     = 98 # /* string */
    TYPE_INFO_SERIAL_NUMBER   = 99 # /* string */
    TYPE_INFO_VERSION_FIXED   = 100 # /* nested */
    TYPE_INFO_VERSION_RUNNING = 101 # /* nested */
    TYPE_INFO_VERSION_STORED  = 102 # /* nested */
    TYPE_INFO_VERSION_NAME    = 103 # /* string */
    TYPE_INFO_VERSION_VALUE   = 104 # /* string */
    PARAM_CMODE_RUNTIME = 0
    PARAM_CMODE_DRIVERINIT = 1
    PARAM_CMODE_PERMANENT= 2
    PARAM_MAX_STR = 32
    # PARAM_TYPE_U8     = 0
    # PARAM_TYPE_U16    = 1
    # PARAM_TYPE_U32    = 2
    # PARAM_TYPE_STRING = 3
    # PARAM_TYPE_BOOL   = 4
    MNL_TYPE_U8            = 1
    MNL_TYPE_U16           = 2
    MNL_TYPE_U32           = 3
    MNL_TYPE_U64           = 4
    MNL_TYPE_STRING        = 5
    MNL_TYPE_FLAG          = 6
    MNL_TYPE_MSECS         = 7
    MNL_TYPE_NESTED        = 8
    MNL_TYPE_NESTED_COMPAT = 9
    MNL_TYPE_NUL_STRING    = 10
    MNL_TYPE_BINARY        = 11

    _struct = {
        TYPE_BUS_NAME: NLAttr._str_struct(True),
        TYPE_DEV_NAME: NLAttr._str_struct(True),
        TYPE_PARAM_NAME: NLAttr._str_struct(True),
        TYPE_PARAM_TYPE: NLAttr._int_struct('B'),
        TYPE_PARAM_VALUE_CMODE: NLAttr._int_struct('B'),
        TYPE_INFO_DRIVER_NAME: NLAttr._str_struct(True),
        TYPE_INFO_SERIAL_NUMBER: NLAttr._str_struct(True),
        TYPE_INFO_VERSION_NAME: NLAttr._str_struct(True),
        TYPE_INFO_VERSION_VALUE: NLAttr._str_struct(True),
    }

class Devlink(object):
    ## linux/include/uapi/linux/devlink.h
    CMD_RELOAD    = 37
    CMD_PARAM_GET = 38
    CMD_PARAM_SET = 39
    CMD_INFO_GET  = 51

    def __init__(self, device, log=None):
        # type: (str, any) -> None
        with GNLConn() as conn:
            self._fid, self._version, cmds = conn.family('devlink')
            self._device = _uevent(device)['pci_slot_name']
            req_cmds = [self.CMD_RELOAD, self.CMD_PARAM_GET, 
                self.CMD_PARAM_SET, self.CMD_INFO_GET]
            if set(req_cmds).difference(set(cmds)):
                raise Exception("kernel does not support"
                    " the required devlink commands")
            self.log = log

    def _log(self, *args): # type: (...) -> None
        if self.log:
            for a in args:
                self.log.write(str(a) + '\n')

    def info(self):
        # type: () -> dict[str, str|dict[str, dict[str, str]]]
        with GNLConn() as conn:
            msgs = conn.send(NLMessage(
                type=self._fid,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_ACK,
                data=GNLConn.Genlmsghdr(
                        cmd=self.CMD_INFO_GET,
                        version=self._version
                    )._bytes +
                    DLAttr(DLAttr.TYPE_BUS_NAME, "pci")._bytes + 
                    DLAttr(DLAttr.TYPE_DEV_NAME, self.device)._bytes
            ))
            for m in msgs:
                if m.type != self._fid:
                    continue
                hdr = GNLConn.Genlmsghdr._from(m.data)
                if hdr.cmd != self.CMD_INFO_GET:
                    continue
                return DLAttr.dict(m.data, hdr._size)

    def param(self, name, modify=None):
        # type: (str, any) -> any
        with GNLConn() as conn:
            ptype = None
            ptype_struct = {
                DLAttr.MNL_TYPE_U8: 'B',
                DLAttr.MNL_TYPE_U16: 'H',
                DLAttr.MNL_TYPE_U32: 'I',
            }
            value = None
            msgs = conn.send(NLMessage(
                type=self._fid,
                flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_ACK,
                data=GNLConn.Genlmsghdr(
                        cmd=self.CMD_PARAM_GET,
                        version=self._version, reserved=0
                    )._bytes + 
                    DLAttr(DLAttr.TYPE_BUS_NAME, "pci")._bytes + 
                    DLAttr(DLAttr.TYPE_DEV_NAME, self._device)._bytes + 
                    DLAttr(DLAttr.TYPE_PARAM_NAME, name)._bytes + 
                    DLAttr(DLAttr.TYPE_PARAM_VALUE_CMODE, 
                        DLAttr.PARAM_CMODE_RUNTIME)._bytes 
            ))
            for m in msgs:
                if m.type != self._fid:
                    continue
                hdr = GNLConn.Genlmsghdr._from(m.data)
                if hdr.cmd != self.CMD_PARAM_GET:
                    continue
                attr = DLAttr.dict(m.data[hdr._size:])
                if DLAttr.TYPE_PARAM in attr:
                    attrs = DLAttr.dict(attr[DLAttr.TYPE_PARAM])
                    if attrs.get(DLAttr.TYPE_PARAM_NAME, None) == name:
                        if DLAttr.TYPE_PARAM_TYPE not in attrs:
                            raise Exception("devlink param type missing")
                        if DLAttr.TYPE_PARAM_VALUES_LIST not in attrs:
                            raise Exception(
                                "devlink param value format missing list")
                        ptype = attrs[DLAttr.TYPE_PARAM_TYPE]
                        pvlist = DLAttr.dict(
                            attrs[DLAttr.TYPE_PARAM_VALUES_LIST]) 
                        pvalue = DLAttr.dict(pvlist[DLAttr.TYPE_PARAM_VALUE])
                        if ptype == DLAttr.MNL_TYPE_FLAG:
                            value = DLAttr.TYPE_PARAM_VALUE_DATA in pvalue
                        elif ptype in ptype_struct:
                            value = unpack(
                                ptype_struct[ptype], 
                                pvalue[DLAttr.TYPE_PARAM_VALUE_DATA]
                            )[0]
                if value is not None:
                    break
            if value is not None and modify is not None and modify != value:
                value = modify
                msg = NLMessage(
                    type=self._fid,
                    flags=NLMessage.FLAG_REQUEST | NLMessage.FLAG_ACK,
                    data=GNLConn.Genlmsghdr(
                            cmd=self.CMD_PARAM_SET,
                            version=self._version, reserved=0
                        )._bytes + 
                        DLAttr(DLAttr.TYPE_BUS_NAME, "pci")._bytes + 
                        DLAttr(DLAttr.TYPE_DEV_NAME, self._device)._bytes + 
                        DLAttr(DLAttr.TYPE_PARAM_NAME, name)._bytes + 
                        DLAttr(DLAttr.TYPE_PARAM_VALUE_CMODE, 
                            DLAttr.PARAM_CMODE_RUNTIME)._bytes + 
                        DLAttr(DLAttr.TYPE_PARAM_TYPE, ptype)._bytes
                )
                if ptype == DLAttr.MNL_TYPE_FLAG and value:
                    msg.data.extend(DLAttr(
                        DLAttr.TYPE_PARAM_VALUE_DATA, b''
                    )._bytes)
                elif ptype in ptype_struct:
                    msg.data.extend(DLAttr(
                        DLAttr.TYPE_PARAM_VALUE_DATA, 
                        pack(ptype_struct[ptype], value)
                    )._bytes)
                else:
                    raise Exception("unknown devlink param type %r" % ptype)
                conn.send(msg)
                self._log(
                    "devlink dev param set"
                    " pci/%s name %s value %s cmode runtime" % 
                    (self._device, name, str(value).lower())
                )
            return value


## helper classes

class Inventory(object):
    _pciids = [
        "8086:1591", # Intel(R) Ethernet Controller E810-C for backplane
        "8086:1592", # Intel(R) Ethernet Controller E810-C for QSFP
        "8086:1593", # Intel(R) Ethernet Controller E810-C for SFP
        "8086:1599", # Intel(R) Ethernet Controller E810-XXV for backplane
        "8086:159A", # Intel(R) Ethernet Controller E810-XXV for QSFP
        "8086:159B", # Intel(R) Ethernet Controller E810-XXV for SFP
        "8086:12D1", # Intel(R) Ethernet Controller E830-CC for backplane
        "8086:12D2", # Intel(R) Ethernet Controller E830-CC for QSFP
        "8086:12D3", # Intel(R) Ethernet Controller E830-CC for SFP
        "8086:12D5", # Intel(R) Ethernet Controller E830-C for backplane
        "8086:12D8", # Intel(R) Ethernet Controller E830-C for QSFP
        "8086:12DA", # Intel(R) Ethernet Controller E830-C for SFP
        "8086:12DC", # Intel(R) Ethernet Controller E830-XXV for backplane
        "8086:12DD", # Intel(R) Ethernet Controller E830-XXV for QSFP
        "8086:12DE", # Intel(R) Ethernet Controller E830-XXV for SFP
        "8086:1889" # Intel(R) iavf 
    ]
    def __init__(self):
        '''
        A target system inventory as a class
        '''
        self.devs = {}
        self.cpus = None
        self.cpus_online = None
        self.numa_cpus = None
        self.numa_nodes = None
        self.refresh()

    def refresh(self):
        '''
        Refresh the system inventopry
        '''
        self._get_cpus()
        self._get_devs()

    @staticmethod
    def _int_list(s): # type: (str) -> list
        '''
        Parse a comma-seperated list of integers with ranges
        '''
        l = []
        for v in str(s).split(','):
            v = v.strip()
            if '-' in v:
                # element is an x-y range
                x, y = v.split('-')
                for i in range(int(x), int(y) + 1):
                    l.append(i)
            else:
                l.append(int(v))
        # remove duplicates and sort 
        return sorted(set(l))

    def _get_cpus(self):
        # cpu topology
        lscpu = _exec(["lscpu"])
        m = re.search(r'^CPU\(s\):\s+(\d+)$', lscpu, re.MULTILINE)
        if not m:
            raise Exception("unable to determine number of CPUs")
        self.cpus = int(m.group(1))
        m = re.search(r'^On-line CPU\(s\) list:\s+([\d,-]+)$', 
            lscpu, re.MULTILINE)
        if not m:
            raise Exception("unable to determine on-line CPUs")
        self.cpus_online = self._int_list(m.group(1))
        # cores for each numa node
        self.numa_cpus = []
        for m in re.finditer("^NUMA node(\d+) CPU\(s\):\s+([\d\-,]+)", 
                lscpu, re.MULTILINE):
            self.numa_cpus.append(self._int_list(m.group(2)))
        self.numa_nodes = len(self.numa_cpus)
        if not self.numa_nodes:
            raise Exception("unable to determine numa topology")

    def _get_devs(self):
        # create list of all network devices
        devs = os.listdir('/sys/class/net/')
        self.devs = {}
        for dev in devs:
            try:
                # query device entry for user events
                info = _uevent(dev)
                # check device for ice or iavf driver
                if (info['driver'] == 'ice' or info['driver'] == 'iavf') and info['pci_id'] in self._pciids:
                    # get device numa node
                    path = os.path.join(*[
                        '/sys', 'class', 'net', dev, 'device', 'numa_node'
                    ])
                    info['numa_node'] = int(_readfile(path))    
                    self.devs[dev] = info
            except:
                pass


class Settings(object):

    def __init__(self, dev, log=None): # type: (str, any) -> None
        self.dev = dev
        self.log = log
        self.tc_offload = None
        self.ntuple_filters = None
        self.flow_director = None
        self._channel_pkt = None
        self.inspect_optimize = None
        self.bp_stop = None
        self.bp_stop_cfg = None
        self.busy_poll = None
        self.busy_read = None
        self.arp_announce = None
        self.arp_ignore = None
        self.arp_notify = None
        self.ethtool = Ethtool(dev, self.log)    
        self.refresh()

    def __str__(self): # type: () -> str
        attrs = [
            'tc_offload',
            'ntuple_filters',
            'flow_director',
            'inspect_optimize',
            'bp_stop',
            'bp_stop_cfg',
            'busy_poll',
            'busy_read',
            'arp_announce',
            'arp_ignore',
            'arp_notify'
        ]
        output = []
        for a in attrs:
            output.append("%s: %r" % (a, getattr(self, a)))
        return '\n'.join(output)

    def _log(self, *args): # type: (...) -> None
        if self.log:
            for a in args:
                self.log.write(str(a) + '\n')

    def refresh(self):
        # get network sysctls
        sysctls = _sysctl('net')
        # store in class attributes
        self.busy_poll = int(sysctls['core.busy_poll'])
        self.busy_read = int(sysctls['core.busy_read'])
        self.arp_announce = \
            int(sysctls['ipv4.conf.' + self.dev + '.arp_announce'])
        self.arp_ignore = int(sysctls['ipv4.conf.' + self.dev + '.arp_ignore'])
        self.arp_notify = int(sysctls['ipv4.conf.' + self.dev + '.arp_notify'])
        # get device features
        features = self.ethtool.features()
        # store in class attributes
        self.tc_offload = features['hw-tc-offload']
        self.ntuple_filters = features['rx-ntuple-filter']
        # get device private flags
        flags = self.ethtool.flags()
        # store in class attributes
        # TODO: not on a VF
        key = 'channel-inline-flow-director'
        if key in flags:
            self.flow_director = True if flags[key] == 'on' else False
        # TODO: END
        self._channel_pkt = 'channel-pkt' \
            if any(['channel-pkt' in key for key in flags]) \
            else 'channel-packet'
        key = self._channel_pkt + '-inspect-optimize'
        if key in flags:
            self.inspect_optimize = True if flags[key] == 'on' else False
        key = self._channel_pkt + '-clean-bp-stop'
        if key in flags:
            self.bp_stop = True if flags[key] == 'on' else False
        key = self._channel_pkt + '-clean-bp-stop-cfg'
        if key in flags:
            self.bp_stop_cfg = True if flags[key] == 'on' else False

    def apply(self):
        # apply network sysctls
        self._log("## network sysctls ##")
        if self.busy_poll is not None:
            _sysctl('net.core.busy_poll', str(self.busy_poll), log=self.log)
        if self.busy_read is not None:
            _sysctl('net.core.busy_read', str(self.busy_read), log=self.log)
        if self.arp_announce is not None:
            _sysctl(
                'net.ipv4.conf.' + self.dev + '.arp_announce', 
                str(self.arp_announce), 
                log=self.log
            )
        if self.arp_ignore is not None:
            _sysctl(
                'net.ipv4.conf.' + self.dev + '.arp_ignore', 
                str(self.arp_ignore), 
                log=self.log
            )
        if self.arp_notify is not None:
            _sysctl(
                'net.ipv4.conf.' + self.dev + '.arp_notify', 
                str(self.arp_notify), 
                log=self.log
            )
        # apply device features
        self._log("## device features ##")
        features = {}
        if self.tc_offload is not None:
            features['hw-tc-offload'] = self.tc_offload
        # TODO: not on a VF
        if self.ntuple_filters is not None:
            features['rx-ntuple-filter'] = self.ntuple_filters
        # TODO: END
        self.ethtool.features(features)
        # apply device private flags
        self._log("## device private flags ##")
        flags = {}
        # TODO: not on a VF
        if self.flow_director is not None:
            flags['channel-inline-flow-director'] = self.flow_director
        # TODO: END
        if self.inspect_optimize is not None:
            flags[self._channel_pkt + '-inspect-optimize'] = \
                self.inspect_optimize
        if self.bp_stop is not None:
            flags[self._channel_pkt + '-clean-bp-stop'] = self.bp_stop
        if self.bp_stop_cfg is not None:
            flags[self._channel_pkt + '-clean-bp-stop-cfg'] = self.bp_stop_cfg
        self.ethtool.flags(flags)        

## config classes
class Filters(object):
    # direction: str = 'ingress', prio: int = 1, proto: str = 'tcp', src_mac: str = None, src_addr: str = None, src_port: int = None, 
    # dst_mac: str = None, dst_addr: str = None, dst_port: int = None, queue: int = None, tc: int = None, action: str = None, priority: int = None
    Filter = namedtuple("Filter", 
    "protocol mac addr port remote_addr remote_port tc queue")
    _filters = []
    def add(self, protocol, mac, addr, port, remote_addr, remote_port, tc, queue):
        # type: (str, str, str, int, str, int, int, int) -> None
        filter = self.Filter(protocol, mac, addr, port, remote_addr, remote_port, tc, queue)
        for f in self._filters:
            score = 0
            for i in range(len(filter) - 2):
                if f[i] == filter[i] or f[i] is None or filter[i] is None:
                    score += 1
            if score == len(filter):
                raise Exception("conflicting mac, addr, port, remote_addr, or remote_port")
        self._filters.append(filter)
    def create(self, dev, skbedit=False, log=None):
        # type: (str, bool, any) -> dict[str, list[TCtool.Filter]]
        tc = TCtool(dev, log)
        for f in self._filters:
            tc.filter_add('ingress', f.tc, f.protocol, src_addr=f.addr, )
            if skbedit:
                tc.filter_add()
        return tc.filter_list()

class ConfigBase(object):
    
    # a dictionary of callables that defines
    # the schema of the config section
    _schema = {}

    ## custom schema formats
    @staticmethod
    def _bool(s): # type (Any) -> bool
        '''
        Parse a <bool> on/off flag 
        '''
        try:
            s = str(s).lower()
            if s in ['on', 'true', 'yes', '1']:
                return True
            elif s in ['off', 'false', 'no', '0', None]:
                return False
            else:
                raise Exception()
        except:
            raise Exception("%r is not a valid boolean" % s)

    @staticmethod
    def _str_lower(s): # type (Any) -> str
        ''' 
        Parse a case insensitive value 
        '''
        return str(s).lower()

    @staticmethod
    def _int_list(s): # type (Any) -> list
        '''
        Parse a comma-seperated list of integers with ranges
        '''
        l = []
        for v in str(s).split(','):
            v = v.strip()
            if '-' in v:
                # element is an x-y range
                x, y = v.split('-')
                for i in range(int(x), int(y) + 1):
                    l.append(i)
            else:
                l.append(int(v))
        # remove duplicates and sort 
        return sorted(set(l))

    @staticmethod
    def _str_list(s): # type (Any) -> list
        ''' 
        Parse a comma-seperated list of strings 
        '''
        l = []
        for v in str(s).split(','):
            l.append(v.strip())
        # remove duplicates and sort 
        return sorted(set(l))

    def __init__(self, name=None): # type: (str) -> None
        self._name = name if name else ""
        self._tcid = None
        self._qpp = 0
        self._queueid = []

    @property
    def _isfiltered(self): # type: () -> bool
        return False

    def __iter__(self): # type: () -> Iterator[tuple[str, ConfigBase]]
        for key in sorted(vars(self)):
            yield key, getattr(self, key)

    def keys(self): # type: () -> list[str]
        return sorted([n for n in vars(self) if n[0] != '_'])
        
    def __getitem__(self, key): # type: (str) -> ConfigBase
        return getattr(self, key)
        
    def _parse(self, conf): # type: (dict) -> None
        ''' 
        Parse a dictionary into attributes using a schema 
        '''
        try:
            for key, value in conf.items():
                # normalize key
                # key = key.strip().lower().replace('-', '').replace('_', '')
                key = key.strip().lower().replace('-', '_')
                if isinstance(value, str):
                    # normalize value
                    value = value.strip()
                    if value.lower() == 'auto' or value == '':
                        value = None
                if isinstance(value, list):
                    value = ','.join([str(v).strip() for v in value])
                if key in self._schema:
                    if value is not None and callable(self._schema[key]):
                        # use schema callable to convert value
                        value = self._schema[key](value)
                    # assign to class attribute
                    setattr(self, key, value)
        except Exception as e:    
            raise Exception("unable to parse configuration: " + str(e))
    
    def _validate(self, inv): # type: (Inventory) -> None
        pass

    def _set_filters(self, dev, skbedit=False, log=None): 
        # type: (str, bool, any) -> None
        pass


class ConfigGlobals(ConfigBase):

    # a dictionary of callables that defines
    # the schema of the config dict/file
    _schema = {
        'arpfilter': ConfigBase._bool, 
        'bpstop': ConfigBase._bool,
        'bpstop_cfg': ConfigBase._bool,
        'busypoll': int,
        'busyread': int,
        'cpus': ConfigBase._int_list,
        'dev': str, 
        'queues': int, 
        'min_rate': int,
        'max_rate': int,
        'numa': ConfigBase._str_lower,
        'optimize': ConfigBase._bool, 
        'priority': ConfigBase._str_lower,
        'queues': int,
        'rxadapt': ConfigBase._bool,
        'rxring': int,
        'rxusecs': int,
        'txadapt': ConfigBase._bool,
        'txring': int,
        'txusecs': int,
    }

    def __init__(self, source=None): # type: (dict) -> None
        '''
        Create a new ConfigGlobals instance 
        optionally from a dictionary
        '''
        super(ConfigGlobals, self).__init__("globals")
        # attributes
        self.arpfilter = False
        self.bpstop = None
        self.bpstop_cfg = None
        self.busypoll = None
        self.busyread = None
        self.cpus = None
        self.dev = None
        self.min_rate = None
        self.max_rate = None
        self.numa = None
        self.optimize = None
        self.priority = None
        self.queues = None
        self.rxadapt = None
        self.rxring = None
        self.rxusecs = None
        self.txadapt = None
        self.txring = None
        self.txusecs = None
        # initialize section with source
        if source is not None:
            if not isinstance(source, dict):
                raise Exception("[globals] source must be a dictionary")
            self._parse(source)

    def __str__(self): # type () -> str
        return str(dict(self))

    def _validate(self, inv): # type: (Inventory) -> None
        '''
        Validate the config global section against a target system inventory
        '''
        # fill in 'auto' values
        if self.dev is None:
            devs = list(inv.devs.keys())
            devs.sort()
            for dev in devs:
                if len(IPtool(dev).addrs()):
                    self.dev = dev
            if self.dev is None:
                raise Exception("[globals] no eligible network devices found,"
                    " please specify one")
        self.queues = 2 if self.queues is None else self.queues
        self.cpus = 'auto' if self.cpus is None else self.cpus
        self.numa = 'all' if self.numa is None else self.numa
        if isinstance(self.cpus, list):
            if len(self.cpus) != self.queues:
                raise Exception(
                    "[globals] the number of cpus must be equal to queues")
        # check if cgroupv1 netprio is available
        if self.priority and self.priority == 'netprio':
            if not os.path.isdir("/sys/fs/cgroup/net_prio"):
                raise Exception("[globals] netprio is not currently available")
        

class ConfigSection(ConfigBase):

    # a dictionary of callables that defines
    # the schema of the config dict/file
    _schema = {
        'addrs': ConfigBase._str_list,
        'cpus': ConfigBase._int_list,
        'mac': str,
        'min_rate': int,
        'max_rate': int,
        'mode': ConfigBase._str_lower,
        'numa': ConfigBase._str_lower,
        'pollers': int,
        'poller_timeout': int,
        'ports': ConfigBase._int_list, 
        'protocol': ConfigBase._str_lower,
        'queues': int,
        'remote_ports': ConfigBase._int_list, 
        'remote_addrs': ConfigBase._str_list,
    }

    @property
    def _isfiltered(self): # type: () -> bool
        return any([self.mac, self.addrs, self.ports, self.remote_addrs, self.remote_ports])

    def __init__(self, name=None, source=None): # type (str, dict) -> None
        '''
        Create a new ConfigSection instance 
        optionally from a dictionary
        '''
        super(ConfigSection, self).__init__(name)
        # attributes
        self.addrs = None
        self.cpus = None
        self.mac = None
        self.min_rate = None
        self.max_rate = None
        self.mode = None
        self.numa = None
        self.pollers = 0
        self.poller_timeout = 10000
        self.ports = None
        self.protocol = None
        self.queues = None
        self.remote_addrs = None
        self.remote_ports = None
        self._filters = []
        # initialize section with source
        if source is not None:
            if not isinstance(source, dict):
                raise Exception("source must be a dictionary")
            self._parse(source)

    def __str__(self): # type () -> str
        return str(dict(self))

    def _validate(self, inv): # type: (Inventory) -> None
        '''
        Validate the config section against a system inventory
        '''
        # fill in 'auto' values
        self.mode = 'exclusive' if self.mode is None else self.mode
        self.protocol = 'tcp' if self.protocol is None else self.protocol
        self.ports = [] if self.ports is None else self.ports
        self.addrs = [] if self.addrs is None else self.addrs
        self.remote_ports = [] if self.remote_ports is None \
            else self.remote_ports
        self.remote_addrs = [] if self.remote_addrs is None \
            else self.remote_addrs
        self.queues = len(self.ports) if self.queues is None \
            and self.mode == 'shared' else self.queues
        self.cpus = 'auto' if self.cpus is None else self.cpus
        self.numa = 'all' if self.numa is None else self.numa
        if self.pollers:
            if self.pollers > self.queues:
                raise Exception("[%s] pollers must not be more than "
                    "the number of queues" % self._name)
            self._qpp = int(math.ceil(float(self.queues) / self.pollers))
            maxpollers = int(math.ceil(float(self.queues) / self._qpp))
            if self.pollers > maxpollers:
                raise Exception("[%s] the number of pollers is incorrect, "
                    "please reduce to %d or set to %d" % 
                    (self._name, maxpollers, self.queues))
        if isinstance(self.cpus, list):
            if self.pollers:
                if len(self.cpus) != self.pollers:
                    raise Exception("[%s] the number of cpus "
                        "must be equal to pollers" % self._name)
            else:
                if len(self.cpus) != self.queues:
                    raise Exception("[%s] the number of cpus "
                        "must be equal to queues" % self._name)
        # check for valid protocol
        if self.protocol not in ['tcp', 'udp']:
            raise Exception("[%s] invalid protocol %r" % 
                (self._name, self.protocol))
        # check for a valid port list
        if len(self.ports) > 1000:
            raise Exception("[%s] the number of ports per section "
                "cannot exceed 1000 entries" % self._name)
        for v in self.ports:
            if v > 65535:
                raise Exception("[%s] invalid port value: %r" % (self._name, v))
        # check if config section is a valid TC description
        if not self.queues:
            raise Exception("[%s] invalid number of queues" % self._name)

    @staticmethod
    def _set_tc_filters(tc, tcid, protocol, addr=None, ports=None, mac=None, skbedit=False): 
        # type: (TCtool, int, str, str, list[int], str, bool) -> None
        if addr and '/' not in addr:
            addr = addr + '/32'
        if ports:
            for port in ports:
                tc.filter_add(
                    'ingress', tcid, protocol, dst_mac=mac, dst_addr=addr, 
                    dst_port=port, tc=tcid
                )
                if skbedit:
                    tc.filter_add(
                        'egress', tcid, protocol, src_mac=mac, src_addr=addr, 
                        src_port=port, action='skbedit', priority=tcid
                    )
        elif addr or mac:
            tc.filter_add(
                'ingress', tcid, protocol, dst_mac=mac, dst_addr=addr, tc=tcid
            )
            if skbedit:
                tc.filter_add(
                    'egress', tcid, protocol, src_mac=mac, src_addr=addr, 
                    action='skbedit', priority=tcid
                )

    @staticmethod
    def _set_tc_filters_remote(tc, tcid, protocol, addr, ports=None, skbedit=False): 
        # type: (TCtool, int, str, str, list[int], bool) -> None
        if addr and '/' not in addr:
            addr = addr + '/32'
        if ports:
            for port in ports:
                tc.filter_add(
                    'ingress', tcid, protocol, src_addr=addr, 
                    src_port=port, tc=tcid
                )
                if skbedit:
                    tc.filter_add(
                        'egress', tcid, protocol, dst_addr=addr, 
                        dst_port=port, action='skbedit', priority=tcid
                    )
        elif addr:
            tc.filter_add(
                'ingress', tcid, protocol, src_addr=addr, tc=tcid
            )
            if skbedit:
                tc.filter_add(
                    'egress', tcid, protocol, dst_addr=addr, 
                    action='skbedit', priority=tcid
                )

    @staticmethod
    def _set_queue_filters(tc, tcid, queue, protocol, addrs=None, port=None, mac=None, skbedit=False): 
        # type: (TCtool, int, int, str, str, int, str, bool) -> None
        if addrs:
            for addr in addrs:             
                if addr and '/' not in addr:
                    addr = addr + '/32'
                tc.filter_add(
                    'ingress', tcid, protocol, dst_mac=mac, dst_addr=addr, 
                    dst_port=port, queue=queue
                )
                if skbedit:
                    tc.filter_add(
                        'egress', tcid, protocol, src_mac=mac, src_addr=addr, 
                        src_port=port, action='skbedit', priority=tcid
                    )
        else:
            tc.filter_add(
                'ingress', tcid, protocol, dst_mac=mac, 
                dst_port=port, queue=queue
            )
            if skbedit:
                tc.filter_add(
                    'egress', tcid, protocol, src_mac=mac, 
                    src_port=port, action='skbedit', priority=tcid
                )

    # def _create_filters(self):
    #     filters = Filters()
    #     if self.addrs:
    #         for addr in self.addrs:
    #             if addr and '/' not in addr:
    #                 addr = addr + '/32'
    #             for port in self.ports:
    #                 filters.add(
    #                     Filter(self.protocol, self.mac, addr, port, None, None)
    #                 )
    #     elif self.ports:
    #         for port in self.ports:
    #             filters.add(
    #                 Filter(self.protocol, self.mac, None, port, None, None)
    #             )
    #     elif self.mac:
    #         filters.add(Filter(self.protocol, self.mac, None, None, None, None))
    #     if self.remote_addrs:
    #         for addr in self.remote_addrs:
    #             if addr and '/' not in addr:
    #                 addr = addr + '/32'
    #             for port in self.remote_ports:
    #                 filters.add(
    #                     Filter(self.protocol, None, None, None, addr, port)
    #                 )
    #     elif self.remote_ports:
    #         for port in self.remote_ports:
    #             filters.add(
    #                 Filter(self.protocol, None, None, None, None, port)
    #             )

    def _set_filters(self, dev, skbedit=False, log=None): 
        # type: (str, bool, any) -> None
        # create ingress & egress filters
        if not self._isfiltered:
            return
        def _tc_filters(self, dev, skbedit, log):
            tc = TCtool(dev, log)
            if self.addrs:
                for addr in self.addrs:
                    self._set_tc_filters(tc, self._tcid, self.protocol, 
                        addr, self.ports, self.mac, skbedit)
            elif self.ports:
                self._set_tc_filters(tc, self._tcid, self.protocol, 
                    None, self.ports, self.mac, skbedit)
            elif self.mac:
                self._set_tc_filters(tc, self._tcid, self.protocol, 
                    None, None, self.mac, skbedit)
            if self.remote_addrs:
                for addr in self.remote_addrs:
                    self._set_tc_filters_remote(tc, self._tcid, self.protocol, 
                        addr, self.remote_ports, skbedit)
            elif self.remote_ports:
                self._set_tc_filters_remote(tc, self._tcid, self.protocol, 
                    None, self.remote_ports, skbedit)
        def _queue_filters(self, dev, skbedit, log):
            tc = TCtool(dev, log)
            for i, port in enumerate(self.ports):
                self._set_queue_filters(tc, self._tcid, self._queueid[i], 
                    self.protocol, None, port, self.mac, skbedit)
        if self.mode == "exclusive":
            _tc_filters(self, dev, skbedit, log)
        elif self.mode == 'shared':
            if len(self.ports) != self.queues:
                raise Exception("[%s] the number of ports must be equal"
                    " to the number of queues when the mode is 'shared'" 
                    % self._name)
            try:
                _queue_filters(self, dev, skbedit, log)
            except:
                _tc_filters(self, dev, skbedit, log)
                ethtool = Ethtool(dev, log)
                for i, port in enumerate(self.ports):
                    ethtool.ntuple_add(
                        proto=self.protocol,
                        dst_port=port, action=self._queueid[i]
                    )

class Config(object):

    def __init__(self, source=None, log=None, verbose=False): 
        # type: (any, str, any, bool) -> None
        '''
        Create a new Config instance 
        optionally from a file-like object, a string, or a dictionary
        '''
        # attributes
        self.globals = ConfigGlobals()
        self._sections = OrderedDict()
        self.log = log
        self.verbose = verbose
        # initialize config with source
        if source is not None:
            if hasattr(source, 'readline'):
                self._load(source)
            if isinstance(source, str):
                self._load(StringIO(source))
            elif isinstance(source, dict):
                self._parse(source)

    def __getattr__(self, attr): # type: (str) -> ConfigBase
        return self._sections[attr]

    def __iter__(self): # type: () -> Iterator[tuple[str, ConfigBase]]
        yield 'globals', self.globals
        for key, value in self._sections.items():
            yield key, value

    def keys(self): # type: () -> list[str]
        return ['globals'] + sorted([k for k in self._sections])
        
    def __getitem__(self, key): # type: (str) -> ConfigBase
        if key == 'globals':
            return OrderedDict(self.globals)
        else:
            return OrderedDict(self._sections[key])

    def __str__(self): # type: () -> str
        return self._dumps()
    
    def _load(self, fp): # type: (any) -> None
        '''
        Loads then parses a config from a file-like object
        '''
        try:
            # load filepath as config file
            conf = SafeConfigParser()
            if sys.version[:1] == '3':
                conf.read_file(fp)
            else:
                conf.readfp(fp)
        except:
            # raise Exception("unable to load %r" % filepath)
            raise
        # convert ConfigParser object to a dict
        config = OrderedDict()
        print(conf.sections())
        for key in conf.sections():
            config[key] = dict(conf.items(key))
        # parse config
        self._parse(config)

    def _parse(self, object): # type: (dict) -> None
        ''' 
        Parse a dictionary into mutiple config sections
        '''
        try:
            # parse global section
            if 'globals' in object:
                self.globals._parse(object['globals'])
                del(object['globals'])
            # parse traffic class sections
            for key in object:
                self._sections[key] = ConfigSection(key, object[key])
            if len(self._sections) > 15:
                raise Exception(
                    "the kernel only supports up to 15 user sections")
        except Exception as e:
            raise Exception("invalid configuration: " + str(e))

    def _print(self, *args): # type: (...) -> None
        if self.verbose:
            for a in args:
                print(str(a))

    def _printhead(self, str): # type: (str) -> None
        if self.verbose:
            _printhead(str)

    def _log(self, *args): # type: (...) -> None
        if self.log:
            for a in args:
                self.log.write(str(a) + '\n')

    def _dumps(self): # type: () -> str
        '''
        Outputs the current config as an INI-formatted string
        '''
        # create ConfigParser object from config dictionary
        conf = SafeConfigParser()
        config = OrderedDict(self)
        conf.add_section('globals')
        for key, value in config['globals'].items():
            if value is not None:
                if isinstance(value, list) or isinstance(value, set):
                    if len(value):
                        value = ','.join([str(v) for v in value])
                    else:
                        value = None
                if value is not None:
                    conf.set('globals', key, str(value))
        del(config['globals'])
        for name, section in config.items():
            conf.add_section(name)
            for key, value in section.items():
                if value is not None:
                    if isinstance(value, list) or isinstance(value, set):
                        if len(value):
                            value = ','.join([str(v) for v in value])
                        else:
                            value = None
                if value is not None:
                    conf.set(name, key, str(value))
        buf = StringIO()
        conf.write(buf)
        return buf.getvalue().strip()

    @staticmethod
    def _cpu_mask(cpu): # type(int) -> str
        '''
        Create CPU mask for a specific core
        '''
        mask = "0"
        if cpu >= 32:
            fill = ""
            zero = "00000000"
            for i in range(cpu // 32):
                fill = fill + ",00000000"
            cpu -= 32 * (cpu // 32)
            mask = "%X%s" % (1 << cpu, fill)
        else:
            mask = "%X" % (1 << cpu)
        return mask

    @property
    def _queues(self): # type: () -> int
        '''
        Returns the currently configured number of combined queues on the NIC
        '''
        return Ethtool(self.globals.dev).channels().combined

    @property
    def _isfiltered(self): # type: () -> bool
        return any([s._isfiltered for _, s in self])

    @property
    def _isshared(self): # type: () -> bool
        return any([s.mode == "shared" for s in self._sections.values()])

    def _check_queues(self): # type() -> None
        '''
        Check if queue list is valid for system
        '''
        # total up the queue list
        requested = self.globals.queues
        for sec in self._sections.values():
            # TODO: check for proper power-of-two queue counts for each TC
            requested += sec.queues
        # if requested > self._queues:
        if requested > 256:
            raise Exception("Not enough queues available")
        
    def _check_rates(self): # type() -> None
        speed = int(_readfile("/sys/class/net/%s/speed" % self.globals.dev))
        requested = self.globals.min_rate if self.globals.min_rate is not None else 0
        for sec in self._sections.values():
            requested += sec.min_rate if sec.min_rate is not None else 0
        if requested > speed:
            raise Exception("Total min_rate exceeds device speed %d" % speed)
        requested = self.globals.max_rate if self.globals.max_rate is not None else 0
        if requested > speed:
            raise Exception("[globals] max_rate exceeds device speed %d" % speed)
        for name, sec in self._sections.items():
            requested = sec.max_rate if sec.max_rate is not None else 0
            if requested > speed:
                raise Exception("[%s] max_rate exceeds device speed %d" % (name, speed))

    def _cleanup(self): # type: () -> None
        '''
        Attempt to cleanup setup from previous run
        '''
        self._printhead("cleanup")
        # turn off napi threads if available
        if os.path.exists("/sys/class/net/%s/threaded" % self.globals.dev):
            _writefile("/sys/class/net/%s/threaded" % self.globals.dev, '0')
        tc = TCtool(self.globals.dev, self.log)
        tc.qdisc_del(tc.TC_H_ROOT, 'mq')
        if self._isfiltered:
            # clear any potentially conflicting qdisc filters
            self._log("## tc filters ##")
            tc.filter_del('ingress')
            self._print("- removed ingress filters")
            if self.globals.priority == 'skbedit':
                tc.filter_del('egress')
                self._print("- removed egress filters")
        if any([t.kind == 'mqprio' for t in tc.qdisc_list()]):
            # clear conflicting qdisc
            self._log("## tc qdisc ##")
            tc.qdisc_del(tc.TC_H_ROOT, 'mqprio')
            self._print("- removed mqprio qdisc")
        # disable any existing pollers
        try:
            devlink = Devlink(self.globals.dev, self.log)
            devlink.param('num_qps_per_poller', 0)
            self._print("- disabled any existing pollers")
        except:
            pass
        # clear any settings
        settings = Settings(self.globals.dev, self.log)
        settings.ntuple_filters = False
        settings.arp_announce = 0
        settings.arp_ignore = 0
        settings.arp_notify = 0
        settings.apply()
        self._print("- cleared any flow rules")

    def _assign_auto_cpus(self, inv): # type: (Inventory) -> None
        # make a list of all available cpus by policy
        devnode = inv.devs[self.globals.dev]['numa_node']
        cpus = {
            'local': inv.numa_cpus[devnode],
            'remote': inv.numa_cpus[(devnode + 1) % inv.numa_nodes],
            'all': []
        }
        for i in range(inv.numa_nodes):
            cpus['all'] += inv.numa_cpus[(devnode + i) % inv.numa_nodes]
            cpus[i] = inv.numa_cpus[i]
        reserved = set()
        for _, section in self:
            if isinstance(section.cpus, list):
                if not set(inv.cpus_online).issuperset(section.cpus):
                    raise Exception("invalid CPU list %r" % section.cpus)
                reserved.update(section.cpus)
        # wrap in 'cycle' iterators that exclude the reserved cpus
        for p in cpus:
            cpus[p] = cycle([c for c in cpus[p] if c not in reserved])
        # generate cpu list for each section that is set to 'auto'
        for section in [s for _, s in self if s.cpus == 'auto']:
            count = section.queues if not getattr(section, 'pollers', 0) \
                else section.pollers
            policy = section.numa
            section.cpus = []
            for _ in range(count):
                section.cpus.append(next(cpus[policy]))
                # TODO: avoid repeat cpu assignment with different policies

    def _set_sysctls(self): # type: () -> None
        # global polling
        if self.globals.busypoll is not None:
            self.settings.busy_poll = self.globals.busypoll
        if self.globals.busyread is not None:
            self.settings.busy_read = self.globals.busyread
        # adjust arp filtering
        if self.globals.arpfilter:
            self.settings.arp_announce = 2
            self.settings.arp_ignore = 1
            self.settings.arp_notify = 1

    def _set_interface_flags(self): # type: () -> None
        # enable tc offload
        self.settings.tc_offload = True
        self.settings.ntuple_filters = True
        # if no sections are 'shared', enable global flow director if available
        if not self._isshared and self.settings.flow_director is not None:
            self.settings.flow_director = True
        # set various tunables
        if self.globals.optimize is not None:
            self.settings.inspect_optimize = self.globals.optimize
        if self.globals.bpstop is not None:
            self.settings.bp_stop = self.globals.bpstop
        if self.globals.bpstop is not None:
            self.settings.bp_stop_cfg = self.globals.bpstop_cfg

    def _set_options(self): # type: () -> None
        self._printhead("setting interface options")
        self._log("## network interface options ##")
        # set coalesce options
        modify = {}
        if self.globals.rxadapt is not None:
            modify["adaptive_rx"] = self.globals.rxadapt
        if self.globals.rxusecs is not None:
            modify["rx_usecs"] = int(self.globals.rxusecs)
        if self.globals.txadapt is not None:
            modify["adaptive_tx"] = self.globals.txadapt
        if self.globals.txusecs is not None:
            modify["tx_usecs"] = int(self.globals.txusecs)
        queues = sum([s.queues for _, s in self])
        queues = set(range(self.globals.queues, queues))
        if len(modify):
            try:
                # try to set coalesce just for application queues
                params = self.settings.ethtool.coalesce_queues(queues)
                params = [p._replace(**modify) for p in params]
                coalesce = self.settings.ethtool.coalesce_queues(queues, params)
            except:
                # if not able to, set globally
                params = self.settings.ethtool.coalesce()
                params = params._replace(**modify)
                coalesce = self.settings.ethtool.coalesce(params)
        else:
            try:
                coalesce = self.settings.ethtool.coalesce_queues(queues)
            except:
                coalesce = self.settings.ethtool.coalesce()
        # display coalesce settings        
        if isinstance(coalesce, list):
            coalesce = coalesce[0]
        self._print(
            "- coalesce settings:",
            "  adaptive-rx: %s" % ("on" if coalesce.adaptive_rx else "off", ),
            "  rx-usecs: %d" % coalesce.rx_usecs,
            "  adaptive-tx: %s" % ("on" if coalesce.adaptive_tx else "off", ),
            "  tx-usecs: %d" % coalesce.tx_usecs,
        )
        # set ring size
        modify = {}
        if self.globals.rxring is not None:
            modify["rx"] = self.globals.rxring
        if self.globals.txring is not None:
            modify["tx"] = self.globals.txring
        params = None
        if len(modify):
            params = self.settings.ethtool.rings()
            params = params._replace(**modify)
        rings = self.settings.ethtool.rings(params)
        # display ring settings
        self._print(
            "- ring parameters:",
            "  rx: %d\n  tx: %d" % (rings.rx, rings.tx)
        )

    def _set_tcs(self): # type: () -> None
        self._printhead("setting traffic classes")
        self._log("## qdisc and tc setup ##")
        tc = TCtool(self.globals.dev, self.log)
        # create root mqprio qdisc
        count = [section.queues for _, section in self]
        min_rate = [section.min_rate for _, section in self]
        max_rate = [section.max_rate for _, section in self]
        pmap = [i for i in range(len(count))]
        offset = [sum(count[:i]) for i in range(len(count))]
        tc.qdisc_add(tc.TC_H_ROOT, 'mqprio', pmap, count, offset,
            min_rate if any(x is not None for x in min_rate) else None,
            max_rate if any(x is not None for x in max_rate) else None
            )
        if self._isfiltered \
                and not any([t.kind == 'clsact' for t in tc.qdisc_list()]):
            # create classifier (ingress+egress) qdisc if needed
            tc.qdisc_add(tc.TC_H_CLSACT, 'clsact')
        # display results
        for t in tc.qdisc_list():
            if t.kind == "mqprio":
                self._print(
                    "number of tcs: %d" % t.num_tc, 
                    "queue count: %r" % [t.count[i] for i in range(t.num_tc)], 
                    "priority map: %r" % [t.map[i] for i in range(t.num_tc)]
                )
        # assign tcs to sections and set per-tc parameters
        devlink = Devlink(self.globals.dev, self.log)
        for i, (name, section) in enumerate(self):
            section._tcid = i
            section._queueid = [offset[i] + x for x in range(count[i])]
            if name == "globals":
                continue
            if self.settings.flow_director is None \
                    and section.mode == "exclusive":
                try:
                    devlink.param('tc%d_inline_fd' % i, True)
                except:
                    _printhead("warning: unable to enable flow director", 93)
            if section.pollers:
                try:
                    devlink.param('tc%d_qps_per_poller' 
                        % i, section._qpp)
                    devlink.param('tc%d_poller_timeout' 
                        % i, int(section.poller_timeout))
                except:
                    raise Exception(
                        "current driver or kernel does not support pollers")

    def _set_filters(self): # type () -> None
        # create filters for each section if needed
        if not self._isfiltered:
            return
        self._printhead("creating filters")
        for name, section in self._sections.items():
            self._log("## filters for section [%s] ##" % name)
            section._set_filters(
                self.globals.dev, self.globals.priority == "skbedit", self.log)
        # display setup
        tc = TCtool(self.globals.dev)
        filters = tc.filter_list()
        if self._isfiltered:
            self._print("- ingress filters:")
            for f in filters['ingress']:
                params = []
                for n, v in f._asdict().items():
                    if v is not None:
                        if n in ['tc', 'action', 'queue']:
                            n = '-> ' + n
                        params.append("%s %s" % (n, str(v)))
                self._print("  %s" % ' '.join(params))
        if self.globals.priority and self.globals.priority == 'skbedit':
            self._print("- egress filters:")
            for f in filters['egress']:
                params = []
                for n, v in f._asdict().items():
                    if v is not None:
                        if n in ['tc', 'action']:
                            n = '-> ' + n
                        params.append("%s %s" % (n, str(v)))
                self._print("  %s" % ' '.join(params))
        if self._isfiltered and self._isshared:
            if not _is_vf(self.globals.dev):
                ntuples = self.settings.ethtool.ntuple_list()
                if ntuples:
                    self._print("- flow rules:")
                    for f in ntuples.values():
                        self._print("  proto %s dst_port %d -> queue %d" % 
                            (f['proto'], f['addr']['dst_port'], f['ring']))

    def _set_affinity(self): # type: () -> None
        self._printhead("setting queue/poller affinity")
        self._log("## queue/poller affinity ##")
        dev = self.globals.dev
        irqs = _irqs(dev)
        if not len(irqs):
            raise Exception("unable to find interrupts for %s" % dev)
        irqs = iter(irqs)
        threaded = any([s.pollers for s in self._sections.values()])
        if threaded:
            # enable napi threads
            napi_threads = []
            if not os.path.exists("/sys/class/net/%s/threaded" % dev):
                raise Exception(
                    "the current kernel or driver does not support napi threads")
            _writefile("/sys/class/net/%s/threaded" % dev, '1')
            self._log("echo 1 > /sys/class/net/%s/threaded" % dev)
            napi_threads = _napi_threads(dev)
            if not len(napi_threads):
                raise Exception("unable to find napi threads for %s" % dev)
            napi_threads = iter(napi_threads)
        # affinitize interrupts/pollers to cores
        for name, section in self:
            count = 0
            for cpu in section.cpus:
                irq = next(irqs)
                _writefile("/proc/irq/%d/smp_affinity_list" % irq, str(cpu))
                self._log("echo %d > /proc/irq/%d/smp_affinity_list" % (cpu, irq))
                self._print("  irq %d -> cpu %d" % (irq, cpu))
                if name != 'globals' and section.pollers:
                    for _ in range(section._qpp):
                        count += 1
                        if count > section.queues:
                            break
                        nthread = next(napi_threads)
                        sched_setaffinity(nthread, [cpu])
                        self._log("# taskset -c %d -p %d" % (cpu, nthread))
                        self._print("  poller thread %d -> %d" % (nthread, cpu))
                elif threaded:
                    next(napi_threads)

    def _set_symmetry(self): # type: () -> None
        self._printhead("setting symmetric queueing")
        self._log("## symmetric queues ##")
        queues = self._queues
        for i in range(queues):
            mask = self._cpu_mask(i)
            _writefile("/sys/class/net/%s/queues/tx-%d/xps_rxqs" % 
                (self.globals.dev, i), mask)
            self._print("  tx queue %d -> rx queue %d" % (i, i))
            self._log("echo %s > /sys/class/net/%s/queues/tx-%d/xps_rxqs" % 
                (mask, self.globals.dev, i))
        for i in range(queues):
            _writefile("/sys/class/net/%s/queues/tx-%d/xps_cpus" % 
                (self.globals.dev, i), '0')
            self._log("echo 0 > /sys/class/net/%s/queues/tx-%d/xps_cpus" % 
                (self.globals.dev, i))

    def add(self, name, object=None): # type: (str, dict) -> None
        ''' 
        Adds the section to the config from a dictionary
        '''
        if name not in self._sections:
            self._parse({name: object})

    def validate(self): # type: () -> None
        '''
        Validates the current config against the target system
        '''
        self.inventory = Inventory()
        for _, section in self:
            section._validate(self.inventory)
        if self.globals.dev not in self.inventory.devs:
            raise Exception("[globals] network device not found or ineligible")
        if self._isshared and _is_vf(self.globals.dev):
                raise Exception("Shared mode is not currently supported on VF netdevs")
        if any([s.pollers for s in self._sections.values()]):
            self.globals.busypoll = 0
            self.globals.busyread = 0
            _printhead("when using pollers, " \
                "busypoll and/or busyread cannot be enabled - " \
                "setting both to zero", 93)
        # check for conflicting filters
        self._assign_auto_cpus(self.inventory)

    def apply(self): # type: () -> None
        '''
        Applies the current config to the target system
        '''
        self._log("### cleanup ###")
        self._cleanup()
        self._check_queues()
        self._check_rates()
        self.settings = Settings(self.globals.dev, self.log)
        self._set_sysctls()
        self._set_interface_flags()
        self._printhead("modifying system and network settings")
        self._log("", "### configuration ###")
        self._print(self.settings)
        self.settings.apply()
        self._set_tcs()
        time.sleep(0.5)
        self._set_filters()
        time.sleep(0.5)
        self._set_options()
        self._log("", "### affinitization ###")
        self._set_affinity()
        self._set_symmetry()


## Check functions

def check_services(log=None, verbose=False): # type (any, bool) -> None
    '''
    Check for potentially troublesome system services
    '''
    if verbose:
        _printhead("checking system services")
    try:
        if _exec(['systemctl', 'status', 'irqbalance'], check=True):
            print("- warning: irqbalance service is installed and running,")
            print("  this may impact performance")
            time.sleep(1)
    except:
        pass

def check_interface(dev, log=None, verbose=False): 
    # type (str, any, bool) -> None
    '''
    Check if interface is functioning and up
    '''
    if verbose:
        _printhead("checking interface %r" % dev)
    if dev is None:
        # TODO: detect first CVL NIC
        #     search /sys/class/net/*/device/driver/module/drivers 
        #     look for a 'pci:ice' symbolic link
        raise Exception("you must provide a network dev")
    else:
        driver = ""
        # check if net dev exists
        if not os.path.isdir("/sys/class/net/%s" % dev):
            raise Exception("%r net dev does not exist" % dev)
        # check if net dev is using the ice or iavf driver
        path = "/sys/class/net/%s/device/driver/module/drivers/pci:%s"
        if os.path.islink(path % (dev, "ice")):
            driver = 'ice'
        elif os.path.islink(path % (dev, "iavf")):
            driver = 'iavf'
        else:
            raise Exception("%r net dev is not using the ice or iavf driver" % dev)
        if verbose:
            version = _readfile((path % (dev, driver)) + "/module/version")
            srcversion = _readfile((path % (dev, driver)) + "/module/srcversion")
            print("driver: %s v%s (%s)" % (driver, version, srcversion))
    ip = IPtool(dev)
    # check link status
    status = ip.link_state()
    if status != 'UP':
        raise Exception("network device %s status is currently %r" 
            % (dev, status))
    if verbose:
        print("link status: %s" % status)
    # check ip addressing
    addresses = ip.addrs()
    if not addresses or not len(addresses):
        raise Exception("unable to determine address of %s" % dev)
    if verbose:
        print("ip addresses: %s" % addresses)

def reload_driver(driver=None, log=None, verbose=False): 
    # (str, bool, any, bool) -> None
    '''
    Reload device driver for the NIC
    '''
    _printhead("reloading device driver")
    driverpath = None
    if driver:
        driverpath = os.path.realpath(os.path.expanduser(driver))
        if not os.path.isfile(driverpath):
            raise Exception("error: %r is not a valid file" % driver)
    if verbose:
        print("- unloading current driver...")
    _exec(['rmmod', 'ice'], log=log, echo=verbose)
    time.sleep(2)
    if log:
        log.write('sleep 2\n')
    if verbose:
        print("- loading driver...")
    if driverpath is None:
        _exec(['modprobe', '-v', 'ice'], log=log, echo=verbose)
    else:
        _exec(['insmod', driverpath], log=log, echo=verbose)
    time.sleep(3)
    if log:
        log.write('sleep 3\n')


def _load(filename=None, isjson=False, log=None): # type (str, bool, any) -> Config
    '''
    Loads a config from a file or stdin and returns a Config object
    '''
    fp = None
    if not filename:
        if not sys.stdin.isatty():
            fp = sys.stdin
        else:
            raise Exception("you must provide a config file")
    else:
        if filename == '-':
            fp = sys.stdin
        elif os.path.isfile(filename):
            fp = open(filename)
        else:
            raise Exception("config file %r not found" % filename)
    _printhead("loading config from %r" % fp.name)
    if isjson:
        return Config(json.load(fp), log=log)
    else:
        return Config(fp, log=log)


def _install():
    '''
    Install this script as /usr/local/bin/adqsetup
    '''
    filename = os.path.realpath(__file__)
    if filename == '/usr/local/bin/adqsetup':
        return
    _printhead("installing this script at /usr/local/bin")
    _exec(["install", "--backup", filename, "/usr/local/bin/adqsetup"])


def _main():
    ''' 
    Main function for CLI
    '''
    if sys.stdin.isatty():
        prolog = [
            "\x1B[33m***\x1B[1m ADQ Setup Tool v%s \x1B[0m\x1B[33m***\x1B[0m" % _VERSION_,
            "\x1B[90mWebsite: https://www.intel.com/content/www/us/en/architecture-and-technology/ethernet/adq-resource-center.html\x1B[0m",
            "\x1B[90mSPDX-License-Identifier: BSD-3-Clause\x1B[0m",
            "\x1B[90mCopyright (c) 2022, Intel Corporation\x1B[0m"
        ]
    else:
        prolog = [
            "*** ADQ Setup Tool v%s ***" % _VERSION_,
            "Website: https://www.intel.com/content/www/us/en/architecture-and-technology/ethernet/adq-resource-center.html",
            "SPDX-License-Identifier: BSD-3-Clause",
            "Copyright (c) 2022, Intel Corporation"
        ]
    prolog.append("\nFor use with Intel Ethernet E810 and E830 Controllers and Network Adapters ONLY")

    for line in prolog: print(line)

    parser = ArgumentParser(
        prog="adqsetup",
        formatter_class=RawDescriptionHelpFormatter, 
        epilog="\n".join([
            "commands:",
            "  apply [FILEPATH]",
            "    * applies a configuration file to the system",
            "    * if no configuration file is given",
            "      attempts to read configuration from stdin",
            "  create [<'[NAME]'> [<PARAM NAME> <PARAM VALUE>] ...] ...",
            "    * creates an adhoc configuration and applies it to the system,",
            "      more than one section is allowed, and the 'globals' section",
            "      may be specified",
            "    * NAME is user-defined and must be unique for each section",
            "  reset",
            "    * attempts to reset/rollback any previous configuration",
            "  persist [FILEPATH]",
            "    * persists a configuration file across reboots using a systemd service unit",
            "    * if no configuration file is given",
            "      attempts to read configuration from stdin",
            "    * one per network device, new configurations overwrite",
            "      any existing persistant one for that network device",
            "  examples",
            "    * creates an 'examples' directory in the current directory",
            "      that contains a number of example configuration files",
            "  install",
            "    * attempts to install a copy of the current script at /usr/local/bin/",
            " ",
            "examples:",
            "  %(prog)s apply /tmp/mysetup.conf",
            "    * applies the setup from the '/tmp/mysetup.conf' config file",
            "  %(prog)s create [app1] queues 6 ports 80,443",
            "    * creates an ADQ-enabled traffic class of 6 queues for ports 80 and 443",
            "  %(prog)s --verbose create [redis] mode shared ports 6379-6382 cpus 2,4,6,8",
            "    * creates a shared traffic class of 4 queues",
            "      for ports 6379 through 6382, affinitized to specific cpus",
            "  %(prog)s --verbose --log=adqsetup.log create \\",
            "        [globals] dev eth4 priority skbedit \\",
            "        [app1] queues 4 ports 80,443 \\",
            "        [app2] queues 2 ports 11211",
            "    * creates an ADQ-enabled traffic class of 4 queues for ports 80 and 443",
            "      and an ADQ-enabled traffic class of 2 queues for port 11211 on the",
            "      'eth4' interface using skbedit to set packet priority"
            " "
        ])
    )

    # parameters
    parser.add_argument('command', metavar='COMMAND', choices=['apply', 'create', 'reset', 'persist', 'examples', 'install', 'help'], 
        help="'apply', 'create', 'reset', 'persist', 'examples', 'install', or 'help'")    
    parser.add_argument('params', metavar='PARAMS', type=str, nargs='*', help="parameters for the command")

    # global options
    parser.add_argument('--dev', '-d', metavar="<NETDEV>", type=str, help="network device", default=SUPPRESS)
    parser.add_argument('--queues', '-q', type=int, help="number of queues for non-ADQ traffic", default=SUPPRESS)
    parser.add_argument('--cpus', type=str, help="cpus for non-ADQ traffic", default=SUPPRESS)
    parser.add_argument('--optimize', '-o', nargs='?', const=True, help="set channel-pkt-inspect-optimize (on/off)", default=SUPPRESS)
    parser.add_argument('--bpstop', '-s', nargs='?', const=True, help="set channel-packet-clean-bp-stop (on/off)", default=SUPPRESS)
    parser.add_argument('--bpstop-cfg', nargs='?', const=True, help="set channel-packet-clean-bp-stop-cfg (on/off)", default=SUPPRESS)
    parser.add_argument('--busypoll', '-b', metavar='<INT>', type=int, help="busy_poll value", default=SUPPRESS)
    parser.add_argument('--busyread', metavar='<INT>', type=int, help="busy_read value", default=SUPPRESS)
    parser.add_argument('--rxadapt', dest='rxadapt', nargs='?', const=True, help="set adaptive rx coalesce (on/off)", default=SUPPRESS)
    parser.add_argument('--rxusecs', dest='rxusecs', metavar='<INT>', type=int, help="rx coalesce usec value", default=SUPPRESS)
    parser.add_argument('--rxring', dest='rxring', metavar='<INT>', type=int, help="rx ring size", default=SUPPRESS)
    parser.add_argument('--txadapt', dest='txadapt', nargs='?', const=True, help="set adaptive tx coalesce (on/off)", default=SUPPRESS)
    parser.add_argument('--txusecs', dest='txusecs', metavar='<INT>', type=int, help="tx coalesce usec value", default=SUPPRESS)
    parser.add_argument('--txring', dest='txring', metavar='<INT>', type=int, help="tx ring size", default=SUPPRESS)
    parser.add_argument('--arpfilter', '-f', action='store_true', help="enable selective ARP activity in order to properly "
        "use more than one interface on the same subnet", default=SUPPRESS)
    parser.add_argument('--priority', '-p', metavar='<METHOD>', choices=['skbedit'], help="method to use for setting socket priority, "
        "possible values are 'skbedit'", default=SUPPRESS)    

    # runtime options
    parser.add_argument('--debug', '-D', action='store_true', help="enable debug mode")
    parser.add_argument('--verbose', '-v', action='store_true', help="enable verbose mode")
    parser.add_argument('--driver', metavar="<FILEPATH>", type=str, help="path for device driver to use", default=None)
    parser.add_argument('--log', '-l', metavar="<FILEPATH>", type=FileType('w'), help="command log file", default=None)
    parser.add_argument('--json', '-j', action='store_true', help="use json for configuration format")
    parser.add_argument('--reload', '-r', action='store_true', help="reload device driver")
    parser.add_argument('--version', '-V', action='version', version='%(prog)s ' + _VERSION_)

    args = parser.parse_args()
    if args.debug:
        args.verbose = True

    try:
        if args.command in ['apply', 'persist']:
            filename = None
            if len(args.params):
                filename = args.params[0]
            config = _load(filename, args.json, args.log)
            config.verbose = args.verbose
        elif args.command == 'create':
            params = copy(args.params)
            if not len(params):
                raise Exception("not enough parameters")
            name = params.pop(0)
            if name[0] == '[' and name[-1] == ']':
                name = name[1:-1]
            else:
                _printhead("warning: the use of section names without "
                    "[ ] brackets is depreciated", 93)
            config = {}
            group = {}
            while len(params):
                n = params.pop(0).replace('-', '_')
                if n[0] == '[' and n[-1] == ']':
                    n = n[1:-1]
                    config[name] = group
                    group = {}
                    name = n
                    continue
                if name == 'globals':
                    if n not in set(vars(ConfigGlobals())):
                        raise Exception("invalid parameter %r" % n)
                else:
                    if n not in set(vars(ConfigSection())):
                        raise Exception("invalid parameter %r" % n)
                try:
                    v = params.pop(0)
                except:
                    raise Exception("missing value for parameter %r" % n)
                group[n] = v
            config[name] = group
            config = Config(config, args.log, args.verbose)
        elif args.command == 'reset':
            config = Config(
                {'tc1': {'queues': 1, 'ports': 1}}, 
                args.log, args.verbose
            )
        elif args.command == 'examples':
            _printhead("creating example config files")
            fpath = os.path.join(os.getcwd(), 'examples')
            if os.path.exists(fpath):
                raise Exception("the directory %r already exists, unable to create example config files" % fpath)
            os.mkdir(fpath)
            for name, data in _examples.items():
                _writefile(os.path.join(fpath, name + ".conf"), data)
            print("- example config files have been created in the directory %r" % fpath)
            return 0
        elif args.command == 'install':
            if os.path.isfile('/usr/local/bin/adqsetup'):
                _printhead("there is already an adqsetup in /usr/local/bin")
            else:
                _install()
            return 0
        elif args.command == 'help':
            parser.print_help()
            return 0

        config._parse({'globals': vars(args)})
        config.validate()

        if args.verbose:
            system = os.uname()
            _printhead("execution environment")
            print("python: %s" % sys.version.split()[0])
            print("host: %s" % socket.gethostname())
            print("system: %s %s" % (system[0].lower(), system[2]))

        if args.command != 'reset':
            _printhead("configuration")
            print(str(config).strip())
            check_services(args.log, args.verbose)

        check_interface(config.globals.dev, args.log, args.verbose)

        if args.command in ['apply', 'create']:
            if args.reload or args.driver:
                reload_driver(args.driver)
            config.apply()
            _printhead("setup complete", 92)
        elif args.command == 'persist':
            if not os.path.isfile('/usr/local/bin/adqsetup'):
                _install()
            _printhead("creating a systemd service for %r using the current config" % config.globals.dev)
            _writefile("/var/lib/adqsetup/%s.conf" % config.globals.dev, config._dumps())
            _writefile("/etc/systemd/system/adqsetup@.service", _service_unit)
            _exec(["systemctl", "daemon-reload"])
            print("- persisted the current config as a systemd service")
            print("- use the 'systemctl enable --now adqsetup@%s' command to enable this service on boot" % config.globals.dev)
        elif args.command == 'reset':
            config._cleanup()
            _printhead("reset complete", 92)
    except Exception as err:
        try:
            config = Config({}, args.log, args.verbose)
            config._parse({'globals': vars(args), 'tc1': {'ports': 0}})
            config._cleanup()
        except:
            pass
        if args.log: 
            args.log.close()
        if args.debug:
            raise
        else:
            _printhead("error occurred! exiting now...", 91)
            print(str(err))
            if isinstance(err, subprocess.CalledProcessError):
                if sys.version[:1] == '3':
                    print(err.output.decode().strip())
                else:
                    print(err.output.strip())
            return 1
    else:
        if args.log: 
            args.log.close()
    return 0


## CLI Entrypoint

if __name__ == "__main__": 
    sys.exit(_main())
