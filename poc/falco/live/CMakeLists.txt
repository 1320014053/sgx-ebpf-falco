cmake_minimum_required(VERSION 3.22)
project(falco_live LANGUAGES C CXX)
option(FALCO_SGX_HARDWARE "Build for non-debug SGX hardware" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(DEPS "${CMAKE_CURRENT_LIST_DIR}/../../build-falco/deps" CACHE PATH "Directory prepared by fetch.sh")
set(LIBS_DIR "${DEPS}/libs")
set(LIBS_PACKAGE_NAME "falcosecurity")
set(DRIVER_NAME falco)
set(DRIVER_DEVICE_NAME falco)
set(DRIVER_VERSION "11.0.1+driver")
set(GIT_COMMIT cea7e1d4fa6f64d3855a8e37d784088ae4846891)
set(BUILD_LIBSCAP_MODERN_BPF ON)
set(BUILD_LIBSCAP_EXAMPLES OFF)
set(CREATE_TEST_TARGETS OFF)
set(ENABLE_ENGINE_KMOD OFF)
set(USE_BUNDLED_DEPS OFF)
set(USE_BUNDLED_LIBBPF ON)
set(UTHASH_INCLUDE "${DEPS}/uthash/src")

list(APPEND CMAKE_MODULE_PATH "${LIBS_DIR}/cmake/modules")
include(compute_versions)
compute_versions("${LIBS_DIR}/driver/API_VERSION" "${LIBS_DIR}/driver/SCHEMA_VERSION")
configure_file("${LIBS_DIR}/driver/driver_config.h.in" driver/src/driver_config.h)
include_directories("${LIBS_DIR}" "${LIBS_DIR}/userspace" "${LIBS_DIR}/driver"
                    "${CMAKE_BINARY_DIR}/driver/src" "${CMAKE_BINARY_DIR}/libscap")
include(libscap)

add_library(falco_ring_map STATIC ring_map.c)
add_dependencies(falco_ring_map ProbeSkeleton)
target_include_directories(falco_ring_map PRIVATE "${LIBS_DIR}/userspace/libpman/src" "${CMAKE_BINARY_DIR}/skel_dir")
target_link_libraries(falco_ring_map PRIVATE pman)

set(OpenEnclave_DIR "${DEPS}/ert/opt/edgelessrt/lib/openenclave/cmake")
find_package(OpenEnclave CONFIG REQUIRED NO_DEFAULT_PATH)
find_package(Threads REQUIRED)
add_custom_command(
    OUTPUT Falco_u.c Falco_u.h Falco_args.h
    COMMAND openenclave::oeedger8r --untrusted "${CMAKE_CURRENT_SOURCE_DIR}/../Falco.edl"
            --search-path "${OE_INCLUDEDIR}" --search-path "${OE_INCLUDEDIR}/openenclave/edl/sgx"
    DEPENDS ../Falco.edl)
add_library(falco_live_host STATIC ../host.cpp "${CMAKE_CURRENT_BINARY_DIR}/Falco_u.c")
target_include_directories(falco_live_host PUBLIC "${CMAKE_CURRENT_BINARY_DIR}" ..)
target_compile_definitions(falco_live_host PUBLIC OE_API_VERSION=2 PRIVATE FALCO_SGX_HARDWARE=$<BOOL:${FALCO_SGX_HARDWARE}>)
target_link_libraries(falco_live_host PUBLIC openenclave::oehost Threads::Threads)
add_executable(falco-live live_host.cpp)
get_target_property(libbpf_headers lbpf INTERFACE_INCLUDE_DIRECTORIES)
add_custom_command(OUTPUT packet_tap.skel.h
    COMMAND "${MODERN_CLANG_EXE}" -target bpf -g -O2 "-I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}"
            "-I${libbpf_headers}" -c "${CMAKE_CURRENT_SOURCE_DIR}/packet_tap.bpf.c" -o packet_tap.bpf.o
    COMMAND "${MODERN_BPFTOOL_EXE}" gen skeleton packet_tap.bpf.o > packet_tap.skel.h
    DEPENDS packet_tap.bpf.c packet_record.h lbpf VERBATIM)
target_sources(falco-live PRIVATE packet_tap.skel.h)
target_link_libraries(falco-live PRIVATE falco_live_host falco_ring_map scap lbpf)
add_executable(httpd workload.c)

add_executable(falco-ring-test ring_test.cpp)
target_link_libraries(falco-ring-test PRIVATE falco_live_host)
target_link_options(falco-ring-test PRIVATE -Wl,--wrap=falco_emit -Wl,--wrap=fflush)

add_executable(replay-ring EXCLUDE_FROM_ALL ../tests/replay-ring.cpp)
target_link_libraries(replay-ring PRIVATE falco_live_host)
