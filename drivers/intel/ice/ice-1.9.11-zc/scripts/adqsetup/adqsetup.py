#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Intel Corporation
#
import sys, os, time, subprocess, pipes, re, json, math
from subprocess import CalledProcessError
from tempfile import NamedTemporaryFile
from copy import copy, deepcopy
from collections import OrderedDict
from argparse import (
    ArgumentParser, 
    SUPPRESS,
    FileType,
    RawDescriptionHelpFormatter
)

if sys.version[:1] == '3':
    # Python 3 imports
    from configparser import ConfigParser as SafeConfigParser
    from io import StringIO
elif sys.version[:1] == '2':
    # Python 2 imports
    from ConfigParser import SafeConfigParser
    from StringIO import StringIO
else:
    raise Exception("Unsupported Python version")

_VERSION_ = '1.2.1'


## public API

__all__ = [
    'Config', 'ConfigGlobals', 'ConfigSection',
    'check_tools', 'check_depends', 'check_driver', 'check_interface'
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

def _printhead(s):
    # type: (str) -> None
    ''' 
    Print a header line with a bold font 
    '''
    if sys.stdin.isatty():
        print("\n** \x1B[1m" + str(s) + "\x1B[0m **")
    else:
        print("\n** " + str(s) + " **")


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
        if sys.version[:1] == '3':
            stdout = stdout.decode().strip()
        else:
            stdout = stdout.strip()

    if stdout and echo:
        print(stdout)

    if check:
        return success
    else:
        return stdout

def _sysctl(key, value=None, log=None):
    # type: (str, any, any) -> str
    '''
    Get or set a sysctl value by key
    '''
    if value is None:
        return _exec(['sysctl', '--values', key], log=log)
    else:
        return _exec(
            ['sysctl', '--write', '%s=%s' % (key, str(value))], 
            check=True, log=log
        )

def _uevent(dev):
    # type: (str) -> dict
    '''
    Get and parse device/uevent entry for device
    '''
    output = _exec(['cat', '/sys/class/net/%s/device/uevent' % dev])
    info = dict(re.findall('^([\w\_]+)=(.*)$', output, re.MULTILINE))
    return {key.lower(): val for key, val in info.items()}

def _ethtool(dev, command, *args, **kwargs): 
    # type: (str, str, *str, **any) -> str
    '''
    Execute ethtool 'command' for device
    '''
    log = kwargs.pop('log', None)
    return _exec(
        ['ethtool', '--' + command, dev] + list(args),
        log=log
    )

def _devlink_param(dev, key, value=None, log=None): 
    # type: (str, str, any, any) -> str
    '''
    Get or set devlink param for device
    '''
    dev = 'pci/' + _uevent(dev)['pci_slot_name']
    if value is None:
        return _exec(
            ['devlink', 'dev', 'param', 'show', dev, 'name', key], 
            log=log
        )
    else:
        return _exec(
            ['devlink', 'dev', 'param', 'set', dev, 'name', 
              key, 'value', str(value), 'cmode', 'runtime'],
            check=True, log=log
        )

def _tc(dev, object, command, *args, **kwargs): 
    # type: (str, str, str, *str, **any) -> str
    log = kwargs.pop('log', None)
    check = kwargs.pop('check', False)
    tc = "tc"
    if os.path.isfile("/opt/iproute2/sbin/tc"):
        tc = "/opt/iproute2/sbin/tc"
    return _exec(
        [tc, object, command, 'dev', dev] + list(args), 
        log=log, check=check
    )

## helper classes

class Inventory(object):
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
            raise Exception("Unable to determine number of CPUs")
        self.cpus = int(m.group(1))
        m = re.search(r'^On-line CPU\(s\) list:\s+([\d,-]+)$', lscpu, re.MULTILINE)
        if not m:
            raise Exception("Unable to on-line CPUs")
        self.cpus_online = self._int_list(m.group(1))
        # cores for each numa node
        self.numa_cpus = []
        for m in re.finditer("^NUMA node(\d+) CPU\(s\):\s+([\d\-,]+)", lscpu, re.MULTILINE):
           self.numa_cpus.append(self._int_list(m.group(2)))
        self.numa_nodes = len(self.numa_cpus)
        if not self.numa_nodes:
            raise Exception("Unable to determine numa topology")

    def _get_devs(self):
        # create list of all network devices
        devs = _exec(['ls', '/sys/class/net/']).split()
        self.devs = {}
        for dev in devs:
            try:
                # query device entry for user events
                info = _uevent(dev)
                # check device for ice driver
                if info['driver'] == 'ice':
                    # get device numa node
                    info['numa_node'] = int(_exec(
                        ['cat', '/sys/class/net/' + dev + '/device/numa_node']
                    ))
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

    def refresh(self):
        # get network sysctls
        stdout = _exec(['sysctl', 'net'])
        sysctls = dict(
            re.findall('^net\.([\w\.\_]+)\s*=\s*(.+)\s*$', stdout, re.MULTILINE)
        )
        # store in class attributes
        self.busy_poll = int(sysctls['core.busy_poll'])
        self.busy_read = int(sysctls['core.busy_read'])
        self.arp_announce = int(sysctls['ipv4.conf.' + self.dev + '.arp_announce'])
        self.arp_ignore = int(sysctls['ipv4.conf.' + self.dev + '.arp_ignore'])
        self.arp_notify = int(sysctls['ipv4.conf.' + self.dev + '.arp_notify'])
        # get device features
        stdout = _ethtool(self.dev, 'show-features')
        features = dict(
            re.findall('^\s*([\w-]+)\s*:\s*(\w+).*$', stdout, re.MULTILINE)
        )
        # store in class attributes
        self.tc_offload = True if features['hw-tc-offload'] == 'on' else False
        self.ntuple_filters = True if features['ntuple-filters'] == 'on' else False
        # get device private flags
        stdout = _ethtool(self.dev, 'show-priv-flags')
        flags = dict(
            re.findall('^\s*([\w-]+)\s*:\s*(\w+).*$', stdout, re.MULTILINE)
        )
        # store in class attributes
        key = 'channel-inline-flow-director'
        if key in flags:
            self.flow_director = True if flags[key] == 'on' else False
        self._channel_pkt = 'channel-pkt' \
            if any(['channel-pkt' in key for key in flags]) else 'channel-packet'
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
        if self.log:
            self.log.write("## network sysctls ##\n")
        if self.busy_poll is not None:
            _sysctl('net.busy_poll', str(self.busy_poll), log=self.log)
        if self.busy_read is not None:
            _sysctl('net.busy_read', str(self.busy_read), log=self.log)
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
        if self.log:
            self.log.write("## device features ##\n")
        if self.tc_offload is not None:
            _ethtool(
                self.dev, 'features', 'hw-tc-offload', 
                'on' if self.tc_offload is True else 'off', 
                log=self.log
            )
        if self.ntuple_filters is not None:
            _ethtool(
                self.dev, 'features', 'ntuple-filters', 
                'on' if self.ntuple_filters is True else 'off', 
                log=self.log
            )
        # apply device private flags
        if self.log:
            self.log.write("## device private flags ##\n")
        if self.flow_director is not None:
            _ethtool(
                self.dev, 'set-priv-flags', 'channel-inline-flow-director', 
                'on' if self.flow_director is True else 'off', 
                log=self.log
            )
        if self.inspect_optimize is not None:
            _ethtool(
                self.dev, 'set-priv-flags', 
                self._channel_pkt + '-inspect-optimize', 
                'on' if self.inspect_optimize is True else 'off', 
                log=self.log
            )
        if self.bp_stop is not None:
            _ethtool(
                self.dev, 'set-priv-flags', 
                self._channel_pkt + '-clean-bp-stop', 
                'on' if self.bp_stop is True else 'off', 
                log=self.log
            )
        if self.bp_stop_cfg is not None:
            _ethtool(
                self.dev, 'set-priv-flags', 
                self._channel_pkt + '-clean-bp-stop-cfg', 
                'on' if self.bp_stop is True else 'off', 
                log=self.log
            )
        

## config classes

class ConfigBase(object):
    
    # a dictionary of callables that defines
    # the schema of the config section
    _schema = {}

    ## custom schema formats
    @staticmethod
    def _bool(s):
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
    def _int_list(s): # type (str) -> list
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
    def _str_list(s): # type (str) -> list
        ''' 
        Parse a comma-seperated list of strings 
        '''
        l = []
        for v in str(s).split(','):
            l.append(v.strip())
        # remove duplicates and sort 
        return sorted(set(l))

    def __iter__(self):
        for key in sorted(vars(self)):
            yield key, getattr(self, key)

    def keys(self):
        return sorted(vars(self))
        
    def __getitem__(self, key):
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
                    value = value.strip().lower()
                    if value == 'auto' or value == '':
                        value = None
                if isinstance(value, list):
                    value = ','.join([str(v) for v in value])
                if key in self._schema:
                    if value is not None and callable(self._schema[key]):
                        # use schema callable to convert value
                        value = self._schema[key](value)
                    # assign to class attribute
                    setattr(self, key, value)
        except Exception as e:    
            raise Exception("unable to parse configuration: " + str(e))


class ConfigGlobals(ConfigBase):

    # a dictionary of callables that defines
    # the schema of the config dict/file
    _schema = {
        'dev': str, 
        'queues': int, 
        'cpus': ConfigBase._int_list,
        'numa': str,
        'optimize': ConfigBase._bool, 
        'bpstop': ConfigBase._bool,
        'bpstop_cfg': ConfigBase._bool,
        'busypoll': int, 
        'busyread': int, 
        'rxadapt': ConfigBase._bool, 
        'txadapt': ConfigBase._bool, 
        'rxusecs': int, 
        'txusecs': int, 
        'rxring': int, 
        'txring': int,
        'arpfilter': ConfigBase._bool, 
        'priority': str
    }

    def __init__(self, source=None): # type: (dict) -> None
        '''
        Create a new ConfigGlobals instance 
        optionally from a dictionary
        '''
        # attributes
        self.dev = None
        self.queues = None
        self.cpus = None
        self.numa = None
        self.optimize = None
        self.bpstop = None
        self.bpstop_cfg = None
        self.busypoll = None
        self.busyread = None
        self.rxadapt = None
        self.rxusecs = None
        self.rxring = None
        self.txadapt = None
        self.txusecs = None
        self.txring = None
        self.arpfilter = False
        self.priority = None

        # initialize section with source
        if source is not None:
            if not isinstance(source, dict):
                raise Exception("source must be a dictionary")
            self._parse(source)

    def __str__(self): # type () -> str
        return str(dict(self))

    def _validate(self, inv): # type: (Inventory) -> None
        '''
        Validate the config global section against a target system inventory
        '''
        # fill in 'auto' values
        if self.dev is None:
            devs = inv.devs.keys()
            devs.sort()
            self.dev = devs[0]
        self.queues = 2 if self.queues is None else self.queues
        self.cpus = 'auto' if self.cpus is None else self.cpus
        self.numa = 'all' if self.numa is None else self.numa

        # determine cpu list for section
        devnode = inv.devs[self.dev]['numa_node']
        if self.cpus == 'auto':
            if self.numa == 'local':
                # only local node
                self.cpus = inv.numa_cpus[devnode][:self.queues]
            elif self.numa == 'remote':
                # only remote node
                self.cpus = inv.numa_cpus[(devnode + 1) % inv.numa_nodes][:self.queues]
            elif self.numa == 'all':
                # local node first
                cpus = []
                for i in range(inv.numa_nodes):
                    cpus += inv.numa_cpus[(devnode + i) % inv.numa_nodes]
                self.cpus = cpus[:self.queues]
            else:
                # specific node
                node = int(self.numa)
                self.cpus = inv.numa_cpus[node][:self.queues]
        else:
            if len(self.cpus) != self.queues:
                raise Exception("cpus must equal the number of queues")

        # remove assigned cpus from inventory
        for cpu in self.cpus:
            for numa in inv.numa_cpus:
                if cpu in numa:
                    numa.remove(cpu)

        # check if cgroupv1 netprio is available
        if self.priority and self.priority == 'netprio':
            if not os.path.isdir("/sys/fs/cgroup/net_prio"):
                raise Exception("netprio is not currently available")
        

class ConfigSection(ConfigBase):

    # a dictionary of callables that defines
    # the schema of the config dict/file
    _schema = {
        'mode': str, 
        'queues': int, 
        'pollers': int,
        'poller_timeout': int,
        'protocol': str,
        'ports': ConfigBase._int_list, 
        'addrs': ConfigBase._str_list,
        'remote_ports': ConfigBase._int_list, 
        'remote_addrs': ConfigBase._str_list,
        'cpus': ConfigBase._int_list, 
        'numa': str
    }

    def __init__(self, source=None): # type (dict) -> None
        '''
        Create a new ConfigSection instance 
        optionally from a dictionary
        '''
        # attributes
        self.mode = None
        self.queues = None
        self.pollers = 0
        self.poller_timeout = 10000
        self.protocol = None
        self.ports = None
        self.addrs = None
        self.remote_ports = None
        self.remote_addrs = None
        self.cpus = None
        self.numa = None

        # initialize section with source
        if source is not None:
            if not isinstance(source, dict):
                raise Exception("source must be a dictionary")
            self._parse(source)

    def __str__(self): # type () -> str
        return str(dict(self))

    def _validate(self, inv, dev): # type: (Inventory, str) -> None
        '''
        Validate the config section against a target system inventory
        '''
        # fill in 'auto' values
        self.mode = 'exclusive' if self.mode is None else self.mode
        self.protocol = 'tcp' if self.protocol is None else self.protocol
        self.ports = [] if self.ports is None else self.ports
        self.remote_ports = [] if self.remote_ports is None else self.remote_ports
        self.queues = len(self.ports) if self.queues is None and self.mode == 'shared' else self.queues
        self.cpus = 'auto' if self.cpus is None else self.cpus
        self.numa = 'all' if self.numa is None else self.numa

        # determine cpu list for section
        devnode = inv.devs[dev]['numa_node']
        if self.cpus == 'auto':
            if self.numa == 'local':
                # only local node
                self.cpus = inv.numa_cpus[devnode][:self.queues]
            elif self.numa == 'remote':
                # only remote node
                self.cpus = inv.numa_cpus[(devnode + 1) % inv.numa_nodes][:self.queues]
            elif self.numa == 'all':
                # local node first
                cpus = []
                for i in range(inv.numa_nodes):
                    cpus += inv.numa_cpus[(devnode + i) % inv.numa_nodes]
                self.cpus = cpus[:self.queues]
            else:
                # specific node
                node = int(self.numa)
                self.cpus = inv.numa_cpus[node][:self.queues]
        else:
            if len(self.cpus) != self.queues:
                raise Exception("cpus must equal the number of queues")

        # remove assigned cpus from inventory
        for cpu in self.cpus:
            for numa in inv.numa_cpus:
                if cpu in numa:
                    numa.remove(cpu)

        # check for valid protocol
        if self.protocol not in ['tcp', 'udp']:
            raise Exception("invalid protocol")

        # check for valid cpu list
        if len(set(inv.cpus_online).intersection(self.cpus)) != len(self.cpus):
            raise Exception("invalid CPU list")

        # check for a valid port list
        for v in self.ports:
            if v > 65535:
                raise Exception("invalid port value: %r" % v)

        # check if config section is a valid TC description
        if not self.queues:
            raise Exception("invalid number of queues")


class Config(object):

    def __init__(self, source=None, log=None): # type: (any, str, any) -> None
        '''
        Create a new Config instance 
        optionally from a file-like object, a string, or a dictionary
        '''
        # attributes
        self.globals = ConfigGlobals()
        self._sections = OrderedDict()
        self._log = log

        # initialize config with source
        if source is not None:
            if hasattr(source, 'readline'):
                self._load(source)
            if isinstance(source, str):
                self._load(StringIO(source))
            elif isinstance(source, dict):
                self._parse(source)

    def __getattr__(self, attr): # type: (str) -> ConfigSection
        return self._sections[attr]

    def __iter__(self):
        yield 'globals', self.globals
        for key, value in self._sections.items():
            yield key, value

    def keys(self):
        return ['globals'] + sorted([k for k in self._sections])
        
    def __getitem__(self, key):
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
            conf.readfp(fp)
        except:
            # raise Exception("unable to load %r" % filepath)
            raise
        # convert ConfigParser object to a dict
        config = {}
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
                self._sections[key] = ConfigSection(object[key])
        except Exception as e:
            raise Exception("invalid configuration file: " + str(e))

    def _dumps(self): # type: () -> str
        '''
        Outputs the current config as an INI-formatted string
        '''
        # create ConfigParser object from config dictionary
        conf = SafeConfigParser()
        config = dict(self)
        conf.add_section('globals')
        for key, value in config['globals'].items():
            if value is not None:
                if isinstance(value, list) or isinstance(value, set):
                    value = ','.join([str(v) for v in value])
                conf.set('globals', key, str(value).lower())
        del(config['globals'])
        for name, section in config.items():
            conf.add_section(name)
            for key, value in section.items():
                if value is not None:
                    if isinstance(value, list) or isinstance(value, set):
                        value = ','.join([str(v) for v in value])
                    conf.set(name, key, str(value).lower())
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
    def _queues(self): # type () -> int
        '''
        Returns the currently configured number of Combined queues on the NIC
        '''
        return int(_exec(
            "ethtool --show-channels %s | grep Combined | awk '{print $2}'" % 
                self.globals.dev, shell=True
            ).split()[1])

    def _check_queues(self): # type() -> None
        '''
        Check if queue list is valid for system
        '''
        # total up the queue list
        requested = self.globals.queues
        for name, sec in self._sections.items():
            # TODO: check for proper power-of-two queue counts for each TC
            requested += sec.queues
        if requested > self._queues:
            raise Exception("Not enough queues available")
        
    def _set_sysctls(self):
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

    def _set_interface_flags(self):
        # enable tc offload
        self.settings.tc_offload = True
        # check if any sections are using the 'shared' mode
        shared = False
        for name, section in self:
            if name != 'globals' and section.mode == 'shared':
                shared = True
                break
        # if no sections are 'shared', enable global flow director if available
        if not shared and self.settings.flow_director is not None:
            self.settings.flow_director = True
        # set various tunables
        if self.globals.optimize is not None:
            self.settings.inspect_optimize = self.globals.optimize
        if self.globals.bpstop is not None:
            self.settings.bp_stop = self.globals.bpstop
        if self.globals.bpstop is not None:
            self.settings.bp_stop_cfg = self.globals.bpstop_cfg

    def _cleanup(self):
        '''
        Attempt to cleanup setup from previous run
        '''
        _printhead("Cleaning up any existing traffic classes and filters")
        # clear any potentially conflicting qdisc filters
        _tc(self.globals.dev, 'filter', 'del', 'ingress', check=True, log=self._log)
        _tc(self.globals.dev, 'filter', 'del', 'egress', check=True, log=self._log)
        # clear any potentially conflicting qdiscs
        _tc(self.globals.dev, 'qdisc', 'del', 'ingress', check=True, log=self._log)
        _tc(self.globals.dev, 'qdisc', 'del', 'root', 'mqprio', check=True, log=self._log)
        _tc(self.globals.dev, 'qdisc', 'del', 'clsact', check=True, log=self._log)
        # disable any existing pollers
        try:
            _devlink_param(self.globals.dev, 'num_qps_per_poller', 0, log=self._log)
        except CalledProcessError:
            pass
        # clear any settings
        settings = Settings(self.globals.dev, self._log)
        settings.ntuple_filters = False
        settings.arp_announce = 0
        settings.arp_ignore = 0
        settings.arp_notify = 0
        settings.apply()

    def _set_tcs(self, echo=False): # type(bool) -> None
        _printhead("Setting traffic classes")
        if self._log:
            self._log.write("## qdisc and tc setup ##\n")

        num_tcs = len(self.keys())

        # construct root qdisc parameters...
        params = ["root", "mqprio", "num_tc", str(num_tcs)]

        # add prio map
        params.append("map")
        for i in range(num_tcs): 
            params.append(str(i))

        # add TC queue specifiers
        params.append("queues")
        queue_idx = 0
        for _, section in self:
            params.append("%d@%d" % (section.queues, queue_idx))
            queue_idx += section.queues

        # add flags
        params.extend(["hw", "1", "mode", "channel"])

        # create root qdisc
        _tc(self.globals.dev, "qdisc", "add", *params, log=self._log)
        
        # create classifier (ingress+egress) qdisc
        _tc(self.globals.dev, "qdisc", "add", "clsact", log=self._log)

        # display results
        if echo:
            output = _tc(self.globals.dev, "qdisc", "show")
            for line in output.split('\n'):
                if 'fq_code' not in line:
                    print(line)

        _printhead("Creating traffic filters")

        # create ingress filters for TCs
        def _filter_params(tc_idx, dir, proto, port, addr=None, egress=False, skbedit=False): 
            # type (int, str, int, str) -> list
            ''' create tc filter params based on match criteria ''' 
            params = ["egress" if egress else "ingress", "prio", str(tc_idx), "protocol", "ip", "flower"]
            if addr is not None:
                params.extend(["%s_ip" % dir, str(addr)])
            params.extend(["ip_proto", proto, "%s_port" % dir, str(port)])
            if skbedit:
                params.extend(["action", "skbedit", "priority", "1"])
            else:
                params.extend(["skip_sw", "hw_tc", str(tc_idx)])
            return params

        tc_idx = 0
        for name, section in self:
            if name != 'globals':
                if section.mode == 'exclusive' and self.settings.flow_director is None:
                    _devlink_param(
                        self.globals.dev, 'tc%d_inline_fd' % tc_idx, 'true',
                        log=self._log
                    )
                for port in section.ports:
                    if section.addrs is not None and len(section.addrs):
                        for addr in section.addrs:
                            if '/' not in addr:
                                addr = addr + '/32'
                            _tc(
                                self.globals.dev, "filter", "add", 
                                *_filter_params(tc_idx, 'dst', section.protocol, port, addr), 
                                log=self._log
                            )
                            if self.globals.priority and self.globals.priority == 'skbedit':
                                _tc(
                                    self.globals.dev, "filter", "add", 
                                    *_filter_params(tc_idx, 'src', section.protocol, port, addr, True, True), 
                                    log=self._log
                                )
                    else:
                        _tc(
                            self.globals.dev, "filter", "add", 
                            *_filter_params(tc_idx, 'dst', section.protocol, port), 
                            log=self._log
                        )
                        if self.globals.priority and self.globals.priority == 'skbedit':
                            _tc(
                                self.globals.dev, "filter", "add", 
                                *_filter_params(tc_idx, 'src', section.protocol, port, None, True, True), 
                                log=self._log
                            )
                for port in section.remote_ports:
                    if section.remote_addrs is not None and len(section.remote_addrs):
                        for addr in section.remote_addrs:
                            if '/' not in addr:
                                addr = addr + '/32'
                            _tc(
                                self.globals.dev, "filter", "add", 
                                *_filter_params(tc_idx, 'src', section.protocol, port, addr), 
                                log=self._log
                            )
                            if self.globals.priority and self.globals.priority == 'skbedit':
                                _tc(
                                    self.globals.dev, "filter", "add", 
                                    *_filter_params(tc_idx, 'dst', section.protocol, port, addr, True, True), 
                                    log=self._log
                                )
                    else:
                        _tc(
                            self.globals.dev, "filter", "add", 
                            *_filter_params(tc_idx, 'src', section.protocol, port), 
                            log=self._log
                        )
                        if self.globals.priority and self.globals.priority == 'skbedit':
                            _tc(
                                self.globals.dev, "filter", "add", 
                                *_filter_params(tc_idx, 'dst', section.protocol, port, None, True, True), 
                                log=self._log
                            )
            tc_idx += 1
                
        # check if any sections are using the 'shared' mode
        # create ntuple sideband filters as needed
        queue_idx = 0
        sideband = False
        for name, section in self:
            if name != 'globals' and section.mode == 'shared':
                if not sideband:
                    _ethtool(self.globals.dev, "features", "ntuple-filters", "on", log=self._log)
                    sideband = True
                for i, port in enumerate(section.ports):
                    _ethtool(self.globals.dev, "config-ntuple", "flow-type", section.protocol + '4',
                        "dst-port", str(port), "action", str(queue_idx), log=self._log)
                    queue_idx += 1
            else:
                queue_idx += section.queues

        # display setup
        # print("* Results")
        if echo:
            print(_tc(self.globals.dev, "filter", "show", "ingress"))
            if self.globals.priority and self.globals.priority == 'skbedit':
                print(_tc(self.globals.dev, "filter", "show", "egress"))
            if sideband:
                print(_ethtool(self.globals.dev, "show-ntuple"))

    def _set_options(self, echo=False): # type (bool) -> None
        _printhead("Setting interface options")
        if self._log:
            self._log.write("## network interface options ##\n")

        # set coalesce options
        params = []
        if self.globals.rxadapt is not None:
            params.extend(["adaptive-rx", "on" if self.globals.rxadapt else "off"])
        if self.globals.rxusecs is not None:
            params.extend(["rx-usecs", str(int(self.globals.rxusecs))])

        # if len(params):
        #     _exec([self._ethtool, "--coalesce", self.globals.dev] + params, check=True, log=self._log)
        
        # params = []

        if self.globals.txadapt is not None:
            params.extend(["adaptive-tx", "on" if self.globals.txadapt else "off"])
        if self.globals.txusecs is not None:
            params.extend(["tx-usecs", str(int(self.globals.txusecs))])

        per_queue = False
        if len(params):
            # calculate bitmask in hex format for application queues
            mask = 0
            queues = sum([o.queues for _, o in self])
            for queue in range(self.globals.queues, queues):
                mask |= 1 << queue
            try:
                # try to set coalesce just for application queues
                _ethtool(
                    self.globals.dev, "per-queue", 'queue_mask', '0x%x' % mask,
                    "--coalesce", *params, log=self._log
                )
                per_queue = True
            except CalledProcessError:
                # if not able to, set globally
                _ethtool(self.globals.dev, "coalesce", *params, log=self._log)
        
        # set ring size
        params = []
        if self.globals.rxring is not None:
            params.extend(["rx", self.globals.rxring])

        if self.globals.txring is not None:
            params.extend(["tx", self.globals.txring])

        if len(params):
            _ethtool(self.globals.dev, "set-ring", *params, log=self._log)

        # display setup
        # print("* Results")
        # print(_exec([self._ethtool,"--show-coalesce", self.globals.dev]))
        if echo:
            if per_queue:
                print(_ethtool(
                    self.globals.dev, "per-queue", "queue_mask", '0x%x' % mask,
                    "--show-coalesce"
                ))
            else:
                print(_ethtool(self.globals.dev, "show-coalesce"))
            print(_ethtool(self.globals.dev, "show-ring"))

    def _set_affinity(self): # type () -> None
        _printhead("Setting interrupt affinity")
        if self._log:
            self._log.write("## queue affinity ##\n")

        # get nic interrupts
        # named: ice-<dev>-TxRx-<queue>
        irqs = _exec("grep -i 'ice-%s-TxRx-' /proc/interrupts | cut -f1 -d:" % self.globals.dev, shell=True)
        irqs = [int(s.strip()) for s in irqs.split("\n")]
        if len(irqs) < 1:
            raise Exception("Unable to find interrupts for %s" % self.globals.dev)
        
        # get a list of assigned cpus
        cpus = []
        for _, section in self:
            cpus.extend(section.cpus)

        # affinitize interrupts to cores
        for i, irq in enumerate(irqs):
            mask = self._cpu_mask(cpus[i % len(cpus)])
            _exec("echo %s > /proc/irq/%d/smp_affinity" % (mask, irq), shell=True, log=self._log)

        # display setup
        print("- Affinitized %d interrupts" % len(irqs))

    def _set_symmetry(self): # type () -> None
        _printhead("Setting symmetric queueing")
        if self._log:
            self._log.write("## symmetric queues ##\n")

        queues = self._queues
        for i in range(queues):
            mask = self._cpu_mask(i)
            _exec("echo %s > /sys/class/net/%s/queues/tx-%d/xps_rxqs" % (mask, self.globals.dev, i), shell=True, log=self._log)
        for i in range(queues):
            _exec("echo 0 > /sys/class/net/%s/queues/tx-%d/xps_cpus" % (self.globals.dev, i), shell=True, log=self._log)

        # display setup
        print("- Aligned %d queues" % queues)

    def _set_pollers(self): # type () -> None
        _printhead("Setting independent pollers")
        if self._log:
            self._log.write("## independent pollers ##\n")
        tc_idx = 0
        for name, section in self:
            if name != 'globals' and section.pollers > 0:
                num_queues = int(math.ceil(float(section.queues) / section.pollers))
                _devlink_param(
                    self.globals.dev, 'tc%d_qps_per_poller' % tc_idx, num_queues,
                    log=self._log
                )
                _devlink_param(
                    self.globals.dev, 'tc%d_poller_timeout' % tc_idx, int(section.poller_timeout),
                    log=self._log
                )
            tc_idx += 1


    def add(self, name, object=None): # type(str, dict) -> None
        ''' 
        Adds the section to the config from a dictionary
        '''
        if name not in self._sections:
            self._parse({name: object})

    def validate(self): # type() -> None
        '''
        Validates the current config against the target system
        '''
        self.inventory = Inventory()
        self.globals._validate(self.inventory)
        for key in self._sections:
            self._sections[key]._validate(self.inventory, self.globals.dev)
        # TODO: check for total queue count

    def apply(self, echo=False): # type(bool) -> None
        '''
        Applies the current config to the target system
        '''
        self.validate()
        if self._log:
            self._log.write("### cleanup ###\n")
        self._cleanup()
        self._check_queues()
        self.settings = Settings(self.globals.dev, self._log)
        self._set_sysctls()
        self._set_interface_flags()
        _printhead("Modifying system and network settings")
        if self._log:
            self._log.write("\n### configuration ###\n")
        print(self.settings)
        self.settings.apply()
        self._set_tcs(echo=echo)
        if sum([section.pollers if name != 'globals' else 0 for name, section in self]):
            self._set_pollers()
        self._set_options(echo=echo)
        if self._log:
            self._log.write("\n### affinitization ###\n")
        self._set_affinity()
        self._set_symmetry()


## Check functions

def check_tools(echo=False): # type (bool) -> None
    '''
    Check for needed system tools and versions
    '''
    _printhead("Checking for needed system tools")

    # search path for tools
    ethtool = _exec(["which", "ethtool"], echo=echo, )
    tc = _exec(["which", "tc"], echo=echo, )
    if os.path.isfile("/opt/iproute2/sbin/tc"):
        tc = "/opt/iproute2/sbin/tc"
    devlink = _exec(["which", "devlink"], echo=echo, )

    # check ethtool version
    out = _exec([ethtool, "--version"], echo=True, )
    ver = re.search("ethtool version (\d+)\.(\d+)", out)
    if not ver:
        print("WARNING: Unable to determine ethtool version")
    else:
        if int(ver.group(1)) < 4 and int(ver.group(2)) < 8:
            raise Exception("Please upgrade your ethtool utility")
        if int(ver.group(1)) == 5 and int(ver.group(2)) < 4:
            print("WARNING: there may be reduced functionality, please upgrade your ethtool utility")

    # check tc version
    out = _exec([tc, "-V"], echo=True, )
    ver = re.search("tc utility, iproute2-ss(\d+)", out)
    if not ver:
        ver = re.search("tc utility, iproute2-(\d+)\.(\d+)", out)
        if not ver:
            print("WARNING: Unable to determine tc version")
        else:
            if int(ver.group(1)) < 4 and int(ver.group(2)) < 18:
                raise Exception("Please upgrade your tc utility")
    else:
        if int(ver.group(1)) < 171112:
            raise Exception("Please upgrade your tc utility")

    # check devlink version
    out = _exec([devlink, "-V"], echo=True, )
    ver = re.search("devlink utility, iproute2-ss(\d+)", out)
    if not ver:
        ver = re.search("devlink utility, iproute2-(\d+)\.(\d+)", out)
        if not ver:
            print("WARNING: Unable to determine devlink version")
        else:
            if int(ver.group(1)) < 4 and int(ver.group(2)) < 18:
                raise Exception("Please upgrade your tc utility")
    else:
        if int(ver.group(1)) < 171112:
            raise Exception("Please upgrade your devlink utility")
    

def check_depends(log=None, echo=False): # type (any, bool) -> None
    '''
    Check for and install any needed dependencies
    '''
    # TODO: add distro check, adapt commands/output as needed
    _printhead("Checking for needed packages")

    packages = []
    packages.append('libcgroup-tools')

    needed = []

    for package in packages:
        if not _exec(['rpm', '-q', package], check=True, ):
            needed.append(package)

    if len(needed):
        _printhead("Installing missing packages")
        _exec(["yum", "-y", "install"] + needed, log=log, echo=echo, )


def check_services(log=None, echo=False): # type (any, bool) -> None
    '''
    Check for potentially troublesome system services
    '''
    _printhead("Checking system services")

    if _exec(['systemctl', 'status', 'irqbalance'], check=True, echo=echo, ):
        print('Warning: irqbalance is installed and running. This may impact performance.')
        time.sleep(2)


def reload_driver(driver=None, log=None, echo=False): # (str, bool, any, bool) -> None
    '''
    Reload device driver for the NIC
    '''
    _printhead("Reloading device driver")
    print("- Unloading current driver...")
    _exec(['modprobe', '-vr', 'ice'], log=log, echo=echo, )
    time.sleep(2)
    if log:
        log.write('sleep 2\n')

    print("- Loading driver...")
    if driver is None:
        _exec(['modprobe', '-v', 'ice'], log=log, echo=echo, )
    else:
        _exec(['insmod', driver], log=log, echo=echo, )
    time.sleep(3)
    if log:
        log.write('sleep 3\n')


# def check_driver(dev, log=None, echo=False): # type (str, any, bool) -> None
#     '''
#     Check ICE driver and version
#     '''
#     _printhead("Checking ICE driver and version")

#     # check ice driver version
#     ver = _exec(['modinfo', '--field=version', 'ice' if driver is None else driver], )
#     print("- Version: %s" % (ver if ver else "not available",))
    
#     if ver:
#         ver = re.match("(\d+)\.(\d+)\.(\d+).*", ver)
#         if not ver:
#             raise Exception("unknown driver version, please install the OOT ice driver")
#         else:
#             ver = ver.groups()
#             if (int(ver[0]) < 1) or (int(ver[1]) < 2):
#                 raise Exception("old ice driver version, please update")

#     verbiage = []

def check_interface(dev, log=None, echo=False): # type (str, any, bool) -> None
    '''
    Check if interface is functioning and up
    '''
    _printhead("Checking interface %r" % dev)

    if dev is None:
        # TODO: detect first CVL NIC
        #     search /sys/class/net/*/device/driver/module/drivers 
        #     look for a 'pci:ice' symbolic link
        raise Exception("you must provide a network dev")
    else:
        # check if net dev exists
        if not os.path.isdir("/sys/class/net/%s" % dev):
            raise Exception("%r net dev does not exist" % dev)
        # check if net dev is using the ice driver
        if not os.path.islink("/sys/class/net/%s/device/driver/module/drivers/pci:ice" % dev):
            raise Exception("%r net dev is not using the ice driver" % dev)
        ice_version = _exec(['cat', "/sys/class/net/%s/device/driver/module/drivers/pci:ice/module/version" % dev], )
        ice_srcversion = _exec(['cat', "/sys/class/net/%s/device/driver/module/drivers/pci:ice/module/srcversion" % dev], )
        print("- Driver: ice v%s (%s)" % (ice_version, ice_srcversion))

    # check link status
    status = _exec("ip link show dev %s | head -n1 | awk '{print $3}'" % dev, 
        shell=True, )
    print("- Link Status: %s" % status)
    
    if "does not exist" in status:
        raise Exception(status)

    if "NO-CARRIER" in status:
        raise Exception("network cable for %s is not connected" % dev)

    # check ip address
    # TODO: support more then one IP address
    address = _exec("ip -f inet -o addr show dev %s | cut -d' ' -f7 | cut -d/ -f1 | head -n1" % dev, 
        shell=True, )

    if "does not exist" in address:
        raise Exception(address)
    if len(address) < 7:
        # can we fix it?
        print("- Attempting to bring up interface via NetworkManager...")
        if _exec(['ifup', dev], check=True, log=log, echo=echo, ):
            time.sleep(2)
            if log:
                log.write('sleep 2\n')
            address = _exec("ip -f inet -o addr show dev %s | cut -d' ' -f7 | cut -d/ -f1 | head -n1" % dev, 
                shell=True, )
        if len(address) < 7:
            raise Exception("Device %s does not have an IP address")

    print("- IP Address: %s" % address)


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
    _printhead("Loading config from %r" % fp.name)
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
    _printhead("Installing this script in the command path")
    _exec(["install", "--backup", filename, "/usr/local/bin/adqsetup"])
    print("- This script has been installed as /usr/local/bin/adqsetup")


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
    prolog.append("For use with Intel Ethernet E810 Controllers and Network Adapters ONLY\n")

    for line in prolog: print(line)

    parser = ArgumentParser(
        prog="adqsetup",
        formatter_class=RawDescriptionHelpFormatter, 
        epilog="\n".join([
            "examples:",
            "  %(prog)s apply mysetup.conf -> applies the setup from a config file",
            "  %(prog)s create nginx queues 6 ports 80,443 -> creates a traffic class of 6 queues for ports 80 and 443",
            "  %(prog)s create redis mode shared ports 6379-6382 cpus 2,4,6,8 -> creates a traffic class of 4 queues",
            "      for ports 6379 through 6382, affinitized to specific cpus",
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
        "use more then one interface on the same subnet", default=SUPPRESS)
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
        elif args.command == 'create':
            params = copy(args.params)
            if not len(params):
                raise Exception("not enough parameters")
            name = params.pop(0)
            group = {}
            while len(params):
                n = params.pop(0)
                if n not in set(vars(ConfigSection())):
                    raise Exception("Invalid parameter %r" % n)
                try:
                    v = params.pop(0)
                except:
                    raise Exception("Missing value for parameter %r" % n)
                group[n] = v
            config = Config({name: group}, log=args.log)
        elif args.command == 'reset':
            config = Config({}, log=args.log)
            config._parse({'globals': vars(args)})
            config._cleanup()
            return 0
        elif args.command == 'examples':
            _printhead("Creating example config files")
            fpath = os.path.join(os.getcwd(), 'examples')
            if os.path.exists(fpath):
                raise Exception("The directory %r already exists, unable to create example config files" % fpath)
            os.mkdir(fpath)
            for name, data in _examples.items():
                with open(os.path.join(fpath, name + ".conf"), 'w') as fp:
                    fp.write(data)
            print("- Example config files have been created in the directory %r" % fpath)
            return 0
        elif args.command == 'install':
            _install()
            return 0
        elif args.command == 'help':
            parser.print_help()
            return 0

        config._parse({'globals': vars(args)})

        # print configuration
        print("- Python: %s" % sys.version.split()[0])
        print("- Host: %s" % _exec(['hostname']))
        print("- Kernel: %s" % _exec(['uname', '-r']))

        _printhead("Configuration")
        print(str(config).strip())
        check_tools(args.verbose)
        check_services(args.log, args.verbose)

        if args.command in ['apply', 'create']:
            if args.reload:
                reload_driver(args.driver, args.log, args.verbose)

        check_interface(config.globals.dev, args.log, args.verbose)

        if args.command in ['apply', 'create']:
            config.apply(args.verbose)
        elif args.command == 'persist':
            config.validate()
            if not os.path.isfile('/usr/local/bin/adqsetup'):
                _install()
            _printhead("Creating a systemd service for %r using the current config" % config.globals.dev)
            _exec(["mkdir", "-p", "/var/lib/adqsetup"], check=True)
            with open("/var/lib/adqsetup/%s.conf" % config.globals.dev, 'w') as fp:
                fp.write(config._dumps())
            with open("/etc/systemd/system/adqsetup@.service", 'w') as fp:
                fp.write(_service_unit)
            _exec(["systemctl", "daemon-reload"])
            print("- Persisted the current config as a systemd service")
            print("- Use the 'systemctl enable --now adqsetup@%s' command to enable this service on boot" % config.globals.dev)
    except Exception as err:
        if args.log: 
            args.log.close()
        if args.debug:
            raise
        else:
            _printhead("\x1B[91mError occurred! Exiting now...\x1B[0m")
            print("-> " + str(err))
            if isinstance(err, subprocess.CalledProcessError):
                if sys.version[:1] == '3':
                    print(err.output.decode().strip())
                else:
                    print(err.output.strip())
            return 1
    return 0


## CLI Entrypoint

if __name__ == "__main__": 
    sys.exit(_main())
