#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""tinygrid against OpenThread, on OpenThread's simulated radio.

An ot-cli-ftd leader forms a network with an SRP server and an off-mesh
routable prefix; a tinygrid node is handed the leader's dataset and has to
attach, answer pings, carry UDP both ways (fragmented too) and register a
service the server then lists.

Usage: interop.py --ot <ot-cli-ftd> --tg <tg_node> [--poll MS] [--keepalive] [--lease]
"""
import argparse
import ipaddress
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time


class Node:
    def __init__(self, name, argv, cwd):
        self.name = name
        self.p = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.q = queue.Queue()
        self.log = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            line = re.sub(r'^(> )+', '', line.rstrip('\n'))  # the CLI prompt
            self.log.append(line)
            self.q.put(line)

    def send(self, cmd):
        self.p.stdin.write(cmd + '\n')
        self.p.stdin.flush()

    def expect(self, pattern, timeout=10.0):
        rx = re.compile(pattern)
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise TimeoutError(f'{self.name}: no /{pattern}/ in {timeout:.0f} s')
            try:
                line = self.q.get(timeout=left)
            except queue.Empty:
                continue
            m = rx.search(line)
            if m:
                return m

    def drain(self):
        while not self.q.empty():
            self.q.get_nowait()

    def cmd(self, c, pattern='^Done', timeout=10.0):
        self.drain()
        self.send(c)
        return self.expect(pattern, timeout)

    def stop(self):
        try:
            self.p.kill()
        except OSError:
            pass


RESULTS = []


def check(name, fn):
    t0 = time.monotonic()
    try:
        fn()
        RESULTS.append((name, True, time.monotonic() - t0))
        print(f'PASS {name} ({time.monotonic() - t0:.1f} s)', flush=True)
    except Exception as e:  # noqa: BLE001 - the harness reports and goes on
        RESULTS.append((name, False, time.monotonic() - t0))
        print(f'FAIL {name}: {e}', flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ot', required=True)
    ap.add_argument('--tg', required=True)
    ap.add_argument('--poll', type=int, default=0, help='0 for an rx-on child, else SED poll ms')
    ap.add_argument('--keepalive', action='store_true', help='also wait out one keep-alive')
    ap.add_argument('--lease', action='store_true',
                    help='also wait out a 120 s SRP lease the node stops renewing')
    ap.add_argument('--robust', action='store_true',
                    help='key rotation, prefix change, leader reset, parent loss '
                         '(needs a node built with a 12 s child timeout)')
    a = ap.parse_args()
    a.ot, a.tg = os.path.abspath(a.ot), os.path.abspath(a.tg)

    work = tempfile.mkdtemp(prefix='tg-sim-')
    ot = Node('ot', [a.ot, '-l', os.path.join(work, 'ot.log'), '1'], work)
    print(f'     work dir {work}', flush=True)
    tg = None
    try:
        for c in ['dataset init new', 'dataset channel 15', 'dataset panid 0xface',
                  'dataset networkkey 00112233445566778899aabbccddeeff',
                  'dataset meshlocalprefix fd11:22:0:0::', 'dataset commit active',
                  'ifconfig up', 'thread start']:
            ot.cmd(c)
        end = time.monotonic() + 20
        while ot.cmd('state', r'^(leader|detached|disabled|child|router)$').group(1) != 'leader':
            if time.monotonic() > end:
                raise TimeoutError('leader never formed')
            time.sleep(0.5)
        ot.cmd('srp server enable')
        ot.cmd('prefix add fd00:db8:1:0::/64 paros')
        # More network data than one frame holds: the Child ID Response then
        # arrives fragmented and MAC-secured, from a parent not yet ours.
        ot.cmd('prefix add fd00:aaaa:1:0::/64 pos')
        ot.cmd('prefix add fd00:aaaa:2:0::/64 pos')
        ot.cmd('route add fd00:bbbb::/48 s')
        ot.cmd('netdata register')
        ds = ot.cmd('dataset active -x', r'^([0-9a-f]{20,})$').group(1)
        ot_mleid = ot.cmd('ipaddr mleid', r'^(fd11:22:[0-9a-f:]+)$').group(1)
        time.sleep(1)

        tg = Node('tg', [a.tg, '2', str(a.poll), work], work)
        tg.expect(r'^ev up')
        addrs = {}

        def attach():
            t0 = time.monotonic()
            tg.send('start ' + ds)
            tg.expect(r'^ev state role=2 ready=1', 30)
            tg.send('state')
            addrs['mleid'] = tg.expect(r'^ev mleid (\S+)').group(1)
            addrs['omr'] = tg.expect(r'^ev omr (\S+)').group(1)
            print(f'     attached and registered in {time.monotonic() - t0:.2f} s; '
                  f'ML-EID {addrs["mleid"]}, OMR {addrs["omr"]}', flush=True)
            mode = 'n' if a.poll else 'rn'
            ot.cmd('child table', r'\|\s*[0-9a-f]{16}\s*\|', 5)

        check('attach as a child, off-mesh address registered', attach)

        def ping(which):
            def f():
                ot.cmd(f'ping {addrs[which]}', r'1 packets received', 10)
            return f

        check('leader pings the ML-EID', ping('mleid'))
        check('leader pings the off-mesh address', ping('omr'))

        def udp_echo(size):
            def f():
                ot.cmd('udp open')
                ot.cmd('udp bind :: 1234')
                ot.drain()
                if size:
                    ot.send(f'udp send {addrs["omr"]} 5540 -s {size}')
                    ot.expect(rf'^{size} bytes from \S+ 5540', 10)
                else:
                    ot.send(f'udp send {addrs["omr"]} 5540 hello')
                    ot.expect(r'^5 bytes from \S+ 5540 hello', 10)
                ot.cmd('udp close')
            return f

        check('UDP echo, one frame', udp_echo(0))
        check('UDP echo, 1000 B (fragmented both ways)', udp_echo(1000))
        check('UDP echo, 1232 B (largest Matter datagram)', udp_echo(1232))

        def tg_sends():
            ot.cmd('udp open')
            ot.cmd('udp bind :: 1234')
            ot.drain()
            tg.send(f'udp {ot_mleid} 1234 fromtg')
            ot.expect(r'^6 bytes from \S+ 5540 fromtg', 10)
            ot.cmd('udp close')

        check('tinygrid sends to the leader', tg_sends)

        def srp_register():
            tg.send('srp host tgnode')
            tg.send('srp add inst1 _matter._tcp 5540 _I0123456789ABCDEF')
            tg.expect(r'^ev srp svc inst1 state 2', 20)
            ot.drain()
            ot.send('srp server host')
            ot.expect(r'^tgnode\.default\.service\.arpa\.', 5)
            ot.expect(r'deleted: false', 5)
            ot.expect(r'addresses: \[' + re.escape(addrs['omr']) + r'\]', 5)
            ot.drain()
            ot.send('srp server service')
            ot.expect(r'^inst1\._matter\._tcp\.default\.service\.arpa\.', 5)
            ot.expect(r'deleted: false', 5)
            ot.expect(r'subtypes: _I0123456789ABCDEF', 5)
            ot.expect(r'port: 5540', 5)

        check('SRP registers host and service', srp_register)

        def srp_second():
            tg.send('srp add inst2 _matterc._udp 5540 _S3')
            tg.expect(r'^ev srp svc inst2 state 2', 20)
            ot.drain()
            ot.send('srp server service')
            ot.expect(r'^inst2\._matterc\._udp\.default\.service\.arpa\.', 5)

        check('SRP adds a second service', srp_second)

        def srp_remove():
            tg.send('srp del inst1')
            tg.expect(r'^ev srp svc inst1 state 0', 20)
            ot.drain()
            ot.send('srp server service')
            m = ot.expect(r'^inst1\._matter\._tcp\.default\.service\.arpa\.', 5)
            ot.expect(r'deleted: true', 5)

        check('SRP removes one service', srp_remove)

        def services():
            """The leader's SRP services: instance -> {deleted, lease, subtypes}."""
            ot.drain()
            n0 = len(ot.log)
            ot.send('srp server service')
            ot.expect(r'^Done', 5)
            out, cur = {}, None
            for line in ot.log[n0:]:
                m = re.match(r'^(\S+)\.default\.service\.arpa\.$', line)
                if m:
                    cur = out.setdefault(m.group(1), {})
                    continue
                m = re.match(r'^\s+(deleted|lease|subtypes): (\S+)$', line)
                if m and cur is not None:
                    cur[m.group(1)] = m.group(2)
            return out

        def srp_lease():
            tg.send('srp add inst3 _matterc._udp 5540 _L840 120')
            tg.expect(r'^ev srp svc inst3 state 2', 20)
            time.sleep(1)  # the round's last update, inst2's lease
            svc = services()
            assert svc['inst3._matterc._udp'].get('lease') == '120', svc
            assert svc['inst2._matterc._udp'].get('lease') == '7200', svc

        check('SRP gives a 120 s lease its own update', srp_lease)

        def resolve():
            tg.send('resolve inst2 _matterc._udp')
            m = tg.expect(r'^ev dns (ok \S+ \d+|fail -?\d+)', 15)
            assert m.group(1) == f'ok {addrs["omr"]} 5540', m.group(1)
            tg.send('resolve nobody _matter._tcp')
            tg.expect(r'^ev dns fail', 15)

        check('DNS-SD resolves a registered instance, and not a missing one', resolve)

        def mcast_rx():
            ot.cmd('udp open')
            ot.cmd('udp bind :: 1234')
            ot.drain()
            tg.drain()
            ot.send('udp send ff03::1 5540 hello')
            tg.expect(r'^ev udp from \S+ 1234 len 5', 10)
            ot.expect(r'^5 bytes from \S+ 5540 hello', 10)
            time.sleep(1)
            assert not any('ev udp from' in l for l in list(tg.q.queue)), 'repeat delivered'
            ot.cmd('udp close')

        # An OpenThread parent queues realm-local multicast for a sleepy child
        # only when it relays it (mesh_forwarder_ftd.cpp); its own is sent
        # direct. A sleepy OpenThread child misses it exactly as this one does.
        if not a.poll:
            check('realm-local multicast arrives once', mcast_rx)

        def mcast_tx():
            ot.cmd('udp open')
            ot.cmd('udp bind :: 1234')
            ot.drain()
            tg.send('mcast 1234 group')
            src = ot.expect(r'^5 bytes from (\S+) 5540 group', 10).group(1)
            assert ipaddress.ip_address(src) == ipaddress.ip_address(addrs['mleid']), src
            ot.cmd('udp close')

        check('realm-local multicast leaves through the parent', mcast_tx)

        def two_children():
            tg2 = Node('tg2', [a.tg, '3', '500', work], work)
            try:
                tg2.expect(r'^ev up')
                tg2.send('start ' + ds)
                tg2.expect(r'^ev state role=2 ready=1', 30)
                tg2.drain()
                tg.drain()
                tg.send('mcast 5540 hi')  # tg2 echoes it back, unicast
                tg2.expect(r'^ev udp from ' + re.escape(addrs['mleid']) + r' 5540 len 2', 10)
                tg.expect(r'^ev udp from \S+ 5540 len 2', 10)
            finally:
                tg2.stop()

        check('a sleepy child hears another child\'s multicast and answers it', two_children)

        def lease_expiry():
            # Every service renews at 80% of the shortest lease. Once the node
            # stops, the 120 s record lapses on its own and the host, left on
            # the longest lease by the last update of each round, stays.
            tg.send('srp del inst3')
            tg.expect(r'^ev srp svc inst3 state 0', 20)
            tg.send('srp add inst3 _matterc._udp 5540 _L840 120')
            tg.expect(r'^ev srp svc inst3 state 2', 20)
            t0 = time.monotonic()
            time.sleep(1)
            tg.stop()
            while services()['inst3._matterc._udp'].get('deleted') != 'true':
                if time.monotonic() - t0 > 180:
                    raise TimeoutError('the 120 s record never lapsed')
                time.sleep(1)
            t = time.monotonic() - t0
            print(f'     120 s record gone {t:.0f} s after its last update', flush=True)
            assert 110 <= t <= 135, f'{t:.0f} s'
            assert services()['inst2._matterc._udp'].get('deleted') == 'false'
            ot.drain()
            ot.send('srp server host')
            ot.expect(r'^tgnode\.default\.service\.arpa\.', 5)
            ot.expect(r'deleted: false', 5)

        if a.lease:
            check('a 120 s lease lapses when the node stops; a 7,200 s one stays', lease_expiry)

        if a.robust:
            def keyrot():
                n = int(ot.cmd('keysequence counter', r'^(\d+)$').group(1))
                ot.cmd('keysequence guardtime 0')
                ot.cmd(f'keysequence counter {n + 1}')
                ot.cmd(f'ping {addrs["mleid"]}', r'1 packets received', 10)
                ot.cmd(f'ping {addrs["omr"]}', r'1 packets received', 10)

            check('key sequence advances; child follows', keyrot)

            def keepalive():
                time.sleep(30)  # two and a half 12 s timeouts
                ot.cmd(f'ping {addrs["mleid"]}', r'1 packets received', 10)
                age = int(ot.cmd('child table', r'\|\s*\d+\s*\|\s*0x[0-9a-f]+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|', 5).group(1))
                assert age < 12, f'child age {age} s'

            check('keep-alive holds the link past the child timeout', keepalive)

            def prefix_change():
                ot.cmd('prefix add fd00:db8:2:0::/64 paros')
                ot.cmd('prefix remove fd00:db8:1:0::/64')
                ot.cmd('netdata register')
                tg.expect(r'^ev omr fd00:db8:2:', 15)
                tg.expect(r'^ev state role=2 ready=1', 15)
                tg.send('state')
                addrs['omr'] = tg.expect(r'^ev omr (\S+)').group(1)
                ot.cmd(f'ping {addrs["omr"]}', r'1 packets received', 10)
                end = time.monotonic() + 15
                while True:
                    ot.drain()
                    ot.send('srp server host')
                    try:
                        ot.expect(r'addresses: \[' + re.escape(addrs['omr']) + r'\]', 2)
                        break
                    except TimeoutError:
                        if time.monotonic() > end:
                            raise
                        time.sleep(1)

            check('off-mesh prefix changes; new address registered and published', prefix_change)

            def leader_reset():
                ot.send('reset')
                time.sleep(1)
                ot.cmd('ifconfig up')
                ot.cmd('thread start')
                # Alone, a rebooted leader spends a while looking for its old
                # partition before it leads again.
                end = time.monotonic() + 150
                while ot.cmd('state', r'^(leader|detached|disabled|child|router)$').group(1) != 'leader':
                    if time.monotonic() > end:
                        raise TimeoutError('leader never came back')
                    time.sleep(1)
                # The simulated leader forgets its local prefix and SRP server
                # across a reset; a border router republishes them.
                ot.cmd('srp server enable')
                ot.cmd('prefix add fd00:db8:2:0::/64 paros')
                ot.cmd('netdata register')
                tg.drain()
                tg.send('state')
                if not tg.expect(r'^ev state role=(\d) ready=(\d)').group(0).endswith('role=2 ready=1'):
                    tg.expect(r'^ev state role=2 ready=1', 90)
                ot.cmd(f'ping {addrs["mleid"]}', r'1 packets received', 15)
                ot.cmd(f'ping {addrs["omr"]}', r'1 packets received', 15)

            check('leader reboots; child is restored or reattaches', leader_reset)

            def parent_loss():
                t0 = time.monotonic()
                tg.drain()
                ot.stop()
                tg.expect(r'^ev state role=1', 40)
                print(f'     detached {time.monotonic() - t0:.1f} s after the parent went silent',
                      flush=True)

            check('parent vanishes; child notices within its timeout', parent_loss)

        if a.keepalive:
            def keepalive():
                # The child timeout is 240 s: survive two keep-alives.
                time.sleep(500)
                ot.cmd(f'ping {addrs["mleid"]}', r'1 packets received', 10)
                ot.cmd('child table', r'\|\s*[0-9a-f]{16}\s*\|', 5)
            check('still attached after two keep-alive periods', keepalive)
    finally:
        if tg:
            tg.stop()
            open(os.path.join(work, 'tg.out'), 'w').write('\n'.join(tg.log) + '\n')
        ot.stop()
        open(os.path.join(work, 'ot.out'), 'w').write('\n'.join(ot.log) + '\n')
    bad = [n for n, ok, _ in RESULTS if not ok]
    print(f'{len(RESULTS) - len(bad)}/{len(RESULTS)} passed')
    if bad:
        print('--- tg log tail ---')
        print('\n'.join((tg.log if tg else [])[-40:]))
        print('--- ot log tail ---')
        print('\n'.join(ot.log[-40:]))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
