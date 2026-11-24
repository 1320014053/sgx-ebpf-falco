add_compile_definitions(MINIMAL_BUILD FALCO_SGX _GNU_SOURCE OE_API_VERSION=2 OE_BUILD_ENCLAVE)
add_compile_options(-fPIE -fstack-protector-strong -fvisibility=hidden -fno-omit-frame-pointer
                    -ffunction-sections -fdata-sections -ftls-model=local-exec)
link_libraries(openenclave::oe_includes)

include("../engine.cmake")
add_subdirectory(container)

# Compile with the same GNU C++ ABI as ertlibc. The SDK target supplies enclave linker flags.
add_library(raven_zeek_trusted STATIC ${detector_sources})
target_compile_definitions(raven_zeek_trusted PRIVATE RZ_ENCLAVE)
target_include_directories(raven_zeek_trusted PRIVATE ${detector_includes})
set(falco_entry_sources enclave.cpp raven_syscalls.cpp cgo_posix.c "${CMAKE_BINARY_DIR}/Falco_t.c")
add_library(falco-enclave-objects OBJECT ${falco_entry_sources})
target_compile_definitions(falco-enclave-objects PRIVATE RZ_ENCLAVE)
add_dependencies(falco-enclave-objects falco-edges)
target_include_directories(falco-enclave-objects PRIVATE "${CMAKE_BINARY_DIR}")
target_link_libraries(falco-enclave-objects PRIVATE falco_engine)
set(falco_enclave_libs falco_engine container_trusted raven_zeek_trusted
    openenclave::oeenclave openenclave::ertlibc openenclave::oehostepoll
    openenclave::oehostsock openenclave::oehostfs openenclave::oehostresolver openenclave::oecryptombedtls)
add_executable(falco-enclave $<TARGET_OBJECTS:falco-enclave-objects>)
target_link_libraries(falco-enclave PRIVATE ${falco_enclave_libs})
add_custom_command(
    OUTPUT test-key.pem
    COMMAND openssl genrsa -3 -out test-key.pem 3072)
if(FALCO_SGX_HARDWARE)
    set(FALCO_ENCLAVE_DEBUG 0)
else()
    set(FALCO_ENCLAVE_DEBUG 1)
endif()
configure_file(enclave.conf "${CMAKE_CURRENT_BINARY_DIR}/enclave.conf" @ONLY)
add_custom_command(
    OUTPUT "${CMAKE_BINARY_DIR}/falco-enclave.signed"
    COMMAND openenclave::oesign sign -e $<TARGET_FILE:falco-enclave> -c "${CMAKE_CURRENT_BINARY_DIR}/enclave.conf" -k test-key.pem
    COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_FILE:falco-enclave>.signed" "${CMAKE_BINARY_DIR}/falco-enclave.signed"
    DEPENDS falco-enclave "${CMAKE_CURRENT_BINARY_DIR}/enclave.conf" test-key.pem)
add_custom_target(sign-falco ALL DEPENDS "${CMAKE_BINARY_DIR}/falco-enclave.signed")

if(FALCO_SGX_FAULT_INJECTION)
    add_library(falco-fault-objects OBJECT ${falco_entry_sources})
    target_compile_definitions(falco-fault-objects PRIVATE RZ_ENCLAVE FALCO_SGX_FAULT_INJECTION)
    add_dependencies(falco-fault-objects falco-edges)
    target_include_directories(falco-fault-objects PRIVATE "${CMAKE_BINARY_DIR}")
    target_link_libraries(falco-fault-objects PRIVATE falco_engine)
    add_executable(falco-fault-enclave $<TARGET_OBJECTS:falco-fault-objects>)
    target_link_libraries(falco-fault-enclave PRIVATE ${falco_enclave_libs})
    add_custom_command(
        OUTPUT "${CMAKE_BINARY_DIR}/falco-fault-enclave.signed"
        COMMAND openenclave::oesign sign -e $<TARGET_FILE:falco-fault-enclave> -c "${CMAKE_CURRENT_BINARY_DIR}/enclave.conf" -k test-key.pem
        COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_FILE:falco-fault-enclave>.signed" "${CMAKE_BINARY_DIR}/falco-fault-enclave.signed"
        DEPENDS falco-fault-enclave "${CMAKE_CURRENT_BINARY_DIR}/enclave.conf" test-key.pem)
    add_custom_target(sign-falco-fault DEPENDS "${CMAKE_BINARY_DIR}/falco-fault-enclave.signed")
endif()
