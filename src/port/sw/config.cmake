# The software port is built for every architecture dmod supports: the release
# passes -DDMOD_TOOLS_NAME=arch/<arch> (this default is only for a local
# build / the host tests).
set(DMOD_TOOLS_NAME "arch/x86_64" CACHE STRING "Name of the tools configuration")
