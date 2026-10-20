# tinygrid

A Thread end device that never routes. It replaces OpenThread under
tinytalk's `matter_thread.h`. Portable C11.

**Does** attach as a child, rx-on or sleepy. Key rotation, off-mesh routable
address, UDP up to 1,280 B, realm-local multicast, ping, SRP, DNS-SD.

**Does not** route, lead, join, commission, CSL, link metrics. Claims Thread
1.1.

19,721 B flash, 10,148 B RAM, LTO release build, with its own radio driver
in place of Nordic's.

## Use

Add as a Zephyr module, with `ports/zephyr/tinygrid.conf` and, on nRF52,
`ports/zephyr/tinygrid-radio.conf`. `CONFIG_TINYGRID_POLL_MS` makes a sleepy
child.

## Test

```sh
make test      # spec vectors, MLE, AES-CCM*, radio filter and timing
make interop   # a host node against an OpenThread leader
```

Needs Mbed TLS 3.6 (`MBEDTLS_PREFIX`). `make interop` also needs `OT_CLI`:

<details>
<summary><code>ot-cli-ftd</code> on OpenThread's simulated radio</summary>

```sh
cmake -S <ncs>/modules/lib/openthread -B build/ot-sim -GNinja \
  -DOT_PLATFORM=simulation -DOT_FTD=ON -DOT_MTD=OFF -DOT_RCP=OFF \
  -DOT_SRP_SERVER=ON -DOT_ECDSA=ON -DOT_SERVICE=ON -DOT_BORDER_ROUTER=ON \
  -DOT_NETDATA_PUBLISHER=ON -DOT_PING_SENDER=ON -DOT_SIMULATION_INFRA_IF=OFF \
  -DOT_DNSSD_SERVER=ON -DOT_DNS_CLIENT=ON
ninja -C build/ot-sim ot-cli-ftd
```

</details>

Apache-2.0
