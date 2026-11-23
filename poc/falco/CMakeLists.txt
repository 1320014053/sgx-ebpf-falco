cmake_minimum_required(VERSION 3.22)
project(sgx_falco LANGUAGES C CXX)
option(FALCO_SGX_HARDWARE "Build for non-debug SGX hardware" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(DEPS "${CMAKE_CURRENT_LIST_DIR}/../build-falco/deps" CACHE PATH "Directory prepared by fetch.sh")
set(LIBS_DIR "${DEPS}/libs")
set(FALCO_DIR "${DEPS}/falco")
set(OpenEnclave_DIR "${DEPS}/ert/opt/edgelessrt/lib/openenclave/cmake")
find_package(OpenEnclave CONFIG REQUIRED NO_DEFAULT_PATH)

set(edl "${CMAKE_CURRENT_SOURCE_DIR}/Falco.edl")
add_custom_command(
    OUTPUT Falco_t.c Falco_t.h Falco_u.c Falco_u.h Falco_args.h
    COMMAND openenclave::oeedger8r --trusted "${edl}" --search-path "${OE_INCLUDEDIR}"
            --search-path "${OE_INCLUDEDIR}/openenclave/edl/sgx"
    COMMAND openenclave::oeedger8r --untrusted "${edl}" --search-path "${OE_INCLUDEDIR}"
            --search-path "${OE_INCLUDEDIR}/openenclave/edl/sgx"
    DEPENDS "${edl}")
add_custom_target(falco-edges DEPENDS Falco_t.c Falco_u.c)

add_executable(falco-sgx host.cpp replay_host.cpp "${CMAKE_CURRENT_BINARY_DIR}/Falco_u.c")
set_target_properties(falco-sgx PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
target_include_directories(falco-sgx PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(falco-sgx PRIVATE OE_API_VERSION=2 FALCO_SGX_HARDWARE=$<BOOL:${FALCO_SGX_HARDWARE}>)
target_link_libraries(falco-sgx PRIVATE openenclave::oehost)

set(detector_sources "${CMAKE_CURRENT_SOURCE_DIR}/plugin/plugin.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/plugin/raven.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/plugin/graph.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/plugin/zeek.cpp")
set(detector_includes "${DEPS}/njson/single_include" "${DEPS}/plugin-sdk/include")
add_library(raven_zeek SHARED ${detector_sources})
set_target_properties(raven_zeek PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
target_include_directories(raven_zeek PRIVATE ${detector_includes})
add_subdirectory(tests)
add_subdirectory(trusted)
