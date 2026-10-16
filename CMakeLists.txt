# SPDX-License-Identifier: ISC
# tinygrid as a Zephyr module: the portable core, PSA crypto, the nRF
# 802.15.4 port and, for tinytalk, matter_thread.h.
if(CONFIG_TINYGRID)
  zephyr_include_directories(include)
  zephyr_library_named(tinygrid)
  zephyr_library_sources(
    src/tg_core.c
    src/tg_dns.c
    src/tg_ip6.c
    src/tg_lowpan.c
    src/tg_mac.c
    src/tg_mle.c
    src/tg_sec.c
    src/tg_srp.c
    ports/psa/tg_psa.c
    ports/zephyr/tg_zephyr.c)
  zephyr_library_sources_ifdef(CONFIG_TINYGRID_MATTER ports/zephyr/matter_thread_tinygrid.c)
  zephyr_library_compile_definitions(TG_CHILD_TIMEOUT_S=${CONFIG_TINYGRID_CHILD_TIMEOUT}u)
endif()
