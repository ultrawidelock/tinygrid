# SPDX-License-Identifier: ISC
# tinygrid as a Zephyr module: the portable core, PSA crypto, a radio port
# (Nordic's driver or tinygrid's own) and, for tinytalk, matter_thread.h.
if(CONFIG_TINYGRID)
  zephyr_include_directories(include)
  zephyr_library_named(tinygrid)
  zephyr_library_sources(
    src/tg_core.c
    src/tg_ip6.c
    src/tg_lowpan.c
    src/tg_mac.c
    src/tg_mle.c
    src/tg_sec.c
    src/tg_srp.c
    ports/psa/tg_psa.c
    ports/zephyr/tg_zephyr.c)
  zephyr_library_sources_ifdef(CONFIG_TINYGRID_RADIO_NRF_802154 ports/zephyr/tg_radio_nrf802154.c)
  zephyr_library_sources_ifdef(CONFIG_TINYGRID_RADIO_OWN ports/zephyr/tg_radio_nrf52.c src/tg_phy.c)
  zephyr_library_sources_ifdef(CONFIG_TINYGRID_DNS src/tg_dns.c)
  zephyr_library_sources_ifdef(CONFIG_TINYGRID_MATTER ports/zephyr/matter_thread_tinygrid.c)
  # On nRF52 the ECB peripheral does the AES blocks, through MPSL.
  if(CONFIG_MPSL AND CONFIG_SOC_SERIES_NRF52)
    zephyr_library_sources(ports/zephyr/tg_aes_mpsl.c)
    zephyr_library_compile_definitions(TG_PSA_AES=0)
  endif()
  # Each optional part is compiled out, not just left unused.
  zephyr_library_compile_definitions(
    TG_DNS=$<BOOL:${CONFIG_TINYGRID_DNS}>
    TG_MCAST=$<BOOL:${CONFIG_TINYGRID_MULTICAST}>)
  if(CONFIG_TINYGRID_POLL_MS EQUAL 0)
    zephyr_library_compile_definitions(TG_SED=0)
  endif()
  zephyr_library_compile_definitions(TG_CHILD_TIMEOUT_S=${CONFIG_TINYGRID_CHILD_TIMEOUT}u)
  zephyr_library_compile_definitions(TG_SRP_LEASE_S=${CONFIG_TINYGRID_SRP_LEASE_S}u)
  # Nordic's driver's defaults build delayed transmit and receive and frame
  # timestamps, for CSL and time sync. A Thread 1.1 child uses neither, and
  # Zephyr exposes no Kconfig for them.
  if(CONFIG_TINYGRID_RADIO_NRF_802154)
    if(TARGET zephyr-802154-interface)
      target_compile_definitions(zephyr-802154-interface INTERFACE
        NRF_802154_DELAYED_TRX_ENABLED=0
        NRF_802154_FRAME_TIMESTAMP_ENABLED=0)
    else()
      message(WARNING "tinygrid: nrf_802154 interface not defined yet; driver left at its defaults")
    endif()
  endif()
endif()
