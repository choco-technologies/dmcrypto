set(DMOD_DMR_PATH ${CMAKE_CURRENT_SOURCE_DIR}/crypto.dmr)

dmod_add_executable(crypto ${DMOD_MODULE_VERSION}
    main.c
)

# dmcrypto (this repository): the API - hashes, random; dmdrvi: the ioctl of its
# /dev/crypto node.
dmod_link_modules(crypto
    dmdrvi@>=2.9
)

target_link_libraries(crypto dmcrypto_if)
