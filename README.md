# tinygrid

A Thread end device that never routes, small enough to sit beside BLE, UWB
and Matter on an nRF52833. It replaces OpenThread under
[tinytalk](../tinytalk)'s `matter_thread.h`.

What it does: attach as a child (receiver always on, or sleepy and polling),
keep the link alive, follow the network's key rotation, configure an
off-mesh routable address from the network data and register it with the
parent, carry UDP (fragmented up to 1,280 B) unicast and to realm-local
multicast (MPL, repeats dropped), answer pings, register services over SRP
and resolve them over DNS-SD.

What it does not: route, lead, join or commission, CSL, link metrics, or
multicast wider than realm-local. It claims Thread 1.1, so a 1.2+ parent
sends it plain 2006 frames.

`ports/zephyr/matter_thread_tinygrid.c` is `matter_thread.h` for both
tinytalk and ultrawidelock (which adds `matter_thread_resolve()`).

## Layout

```
include/tinygrid/   tg.h (the API), tg_plat.h (what a port provides) and
                    tg_phy.h (radio logic for a port without a vendor driver)
src/                the stack, portable C11: MAC, 6LoWPAN, IPv6, MLE, SRP
ports/psa/          AES, HMAC and the SRP key on PSA Crypto
ports/zephyr/       the radio (Nordic's nRF 802.15.4 driver, or tinygrid's
                    own in the Bluetooth controller's gaps: MPSL timeslots
                    next to Nordic's controller, the Zephyr controller's
                    scheduler otherwise), settings, a thread;
                    matter_thread.h for tinytalk; tinygrid.conf
ports/host/         OpenThread's simulated radio, for tests
tests/host/         unit tests
tests/sim/          a host node and the interop harness
baseline/           size measurement of the OpenThread it replaces
```

## Build and test

| Command | What it does |
|---|---|
| `make test` | Unit tests: the Thread spec's key-derivation vectors, OpenThread's MLE encryption vector, AES-CCM* against PSA, the radio's frame filter and timing |
| `make interop` | A host node against an OpenThread leader on its simulated radio: rx-on, sleepy, then key rotation, keep-alive, prefix change, leader reboot and parent loss; DNS-SD and realm-local multicast, child to child included |
| `baseline/build.sh <tinytalk> <dir> tinygrid` | tinytalk's door-lock on the DWM3001CDK with tinygrid, from inside an nRF Connect SDK v3.3.0 workspace |

`make` needs Mbed TLS 3.6 (`MBEDTLS_PREFIX`). `make interop` needs an
`ot-cli-ftd` built for OpenThread's simulation platform (`OT_CLI`), e.g.
from the SDK's own copy:

```
cmake -S <ncs>/modules/lib/openthread -B build/ot-sim -GNinja \
  -DOT_PLATFORM=simulation -DOT_FTD=ON -DOT_MTD=OFF -DOT_RCP=OFF \
  -DOT_SRP_SERVER=ON -DOT_ECDSA=ON -DOT_SERVICE=ON -DOT_BORDER_ROUTER=ON \
  -DOT_NETDATA_PUBLISHER=ON -DOT_PING_SENDER=ON -DOT_SIMULATION_INFRA_IF=OFF \
  -DOT_DNSSD_SERVER=ON -DOT_DNS_CLIENT=ON
ninja -C build/ot-sim ot-cli-ftd
```

In an application, add this repository as a Zephyr module and
`ports/zephyr/tinygrid.conf` as an extra conf file. `CONFIG_TINYGRID_POLL_MS`
picks a sleepy child. `ports/zephyr/tinygrid-radio.conf` after it swaps
Nordic's radio driver for tinygrid's own (nRF52, 22 to 26 KB less flash;
commissioned, locked and unlocked from Apple Home on a DWM3001CDK on
2026-10-18).

## License

Apache-2.0, see LICENSE and NOTICE.
