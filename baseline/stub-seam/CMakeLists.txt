# Measurement scaffolding only: matter_thread.h with no Thread stack behind it,
# so a build with CONFIG_OPENTHREAD=n shows what the image costs without one.
# Only where tinytalk is: sysbuild hands every module to MCUboot as well.
if(CONFIG_TINYTALK)
  zephyr_library()
  zephyr_library_sources(stub_seam.c)
endif()
