set(USE_AVX512BW OFF)
set(USE_AVX2 OFF)
set(USE_NEON OFF)
add_subdirectory("${DEPS}/reflex" reflex EXCLUDE_FROM_ALL)

set(upstream "${DEPS}/plugins/plugins/container/src")
set(worker "${DEPS}/plugins/plugins/container/go-worker")
set(CMAKE_PROJECT_NAME container)
set(CMAKE_PROJECT_VERSION 0.7.6)
set(CMAKE_PROJECT_DESCRIPTION "Falco container metadata enrichment Plugin")
configure_file("${upstream}/macros.h.in" macros.h @ONLY)

find_program(ERT_GO ertgo PATHS "${DEPS}/ert/opt/edgelessrt/bin" NO_DEFAULT_PATH REQUIRED)
set(worker_archive "${CMAKE_CURRENT_BINARY_DIR}/libworker.a")
file(GLOB_RECURSE worker_sources CONFIGURE_DEPENDS "${worker}/*.go")
add_custom_command(
    OUTPUT "${worker_archive}" "${CMAKE_CURRENT_BINARY_DIR}/libworker.h"
    COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=1 GOTOOLCHAIN=local
            "${ERT_GO}" build -tags containers_image_openpgp "-ldflags=-s -w"
            -buildmode=c-archive -o "${worker_archive}" .
    DEPENDS ${worker_sources} "${worker}/go.mod" "${worker}/go.sum"
    WORKING_DIRECTORY "${worker}"
    VERBATIM)
add_custom_target(container-worker DEPENDS "${worker_archive}" "${CMAKE_CURRENT_BINARY_DIR}/libworker.h")

file(GLOB sources "${upstream}/*.cpp" "${upstream}/matchers/*.cpp")
add_library(container_trusted STATIC api.cpp ${sources}
    "${upstream}/caps/async/async.cpp"
    "${upstream}/caps/extract/extract.cpp" "${upstream}/caps/parse/parse.cpp"
    "${upstream}/caps/listening/listening.cpp")
add_dependencies(container_trusted container-worker)
target_compile_features(container_trusted PRIVATE cxx_std_20)
target_compile_definitions(container_trusted PRIVATE _HAS_ASYNC _HAS_EXTRACT _HAS_PARSE _HAS_LISTENING FMT_HEADER_ONLY)
target_include_directories(container_trusted PRIVATE "${upstream}" "${CMAKE_CURRENT_BINARY_DIR}"
    "${DEPS}/plugin-sdk/include" "${DEPS}/plugin-sdk/include/falcosecurity/internal/deps" "${DEPS}/fmt/include")
target_link_libraries(container_trusted PRIVATE ReflexLibStatic "${worker_archive}")
