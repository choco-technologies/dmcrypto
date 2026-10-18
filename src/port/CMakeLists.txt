# ======================================================================
#               dmcrypto_port Module Configuration
# ======================================================================

# Name of the module
set(DMOD_MODULE_NAME        dmcrypto_port)

# Version is already set above and used in project()

# Author (should be string)
set(DMOD_AUTHOR_NAME        "Patryk Kubiak")

# Stack size for the module (should be integer)
set(DMOD_STACK_SIZE         1024)

# Sources: "sw" is the software port alone. A family's hardware port is its
# own port.c plus the code shared by the STM32 families; whatever the family's
# peripherals do not do is compiled in from sw/ (list those files here as the
# algorithms are written: the software algorithms live in sw/ one file each,
# so a hardware port takes only the ones it needs).
if(DMOD_CPU_FAMILY STREQUAL "sw")
    set(DMCRYPTO_PORT_SOURCES sw/port.c)
elseif(DMOD_CPU_FAMILY MATCHES "^stm32")
    set(DMCRYPTO_PORT_SOURCES ${DMOD_CPU_FAMILY}/port.c stm32_common/stm32_common.c)
else()
    message(FATAL_ERROR "No dmcrypto port for CPU family '${DMOD_CPU_FAMILY}'")
endif()

# Path to the DMR file for this module
set(DMOD_DMR_PATH           ${CMAKE_SOURCE_DIR}/dmcrypto_port.dmr)

#
#   dmod_add_library - create a library module
#   it has the same signature as add_library
#   and can be used in the same way after the creation
#   (for example, to link libraries)
#
dmod_add_library(${DMOD_MODULE_NAME} ${DMOD_MODULE_VERSION}
    # List of source files - can include C and C++ files
    ${DMCRYPTO_PORT_SOURCES}
)

# What dmcrypto_get_capabilities() reports as the port's name
target_compile_definitions(${DMOD_MODULE_NAME} PRIVATE DMCRYPTO_PORT_LABEL="${DMOD_CPU_FAMILY}")

# To depend on another module's headers, use:
#   dmod_link_modules(${DMOD_MODULE_NAME}
#       other_module@1.0
#   )

target_include_directories(${DMOD_MODULE_NAME} BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(${DMOD_MODULE_NAME}_if INTERFACE
    ${CMAKE_SOURCE_DIR}/include
)
