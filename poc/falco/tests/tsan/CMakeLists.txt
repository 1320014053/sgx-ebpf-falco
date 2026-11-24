cmake_minimum_required(VERSION 3.22)
project(falco_concurrency LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(DEPS "${CMAKE_CURRENT_LIST_DIR}/../../../build-falco/deps" CACHE PATH "Directory prepared by fetch.sh")
set(LIBS_DIR "${DEPS}/libs")
set(FALCO_DIR "${DEPS}/falco")
find_package(Threads REQUIRED)
add_compile_definitions(MINIMAL_BUILD FALCO_SGX _GNU_SOURCE)
add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g1 -O1)
add_link_options(-fsanitize=thread)
include("../../engine.cmake")

# The plugin is linked statically, as in the enclave, but reads its stream from a file.
set(plugin "${CMAKE_CURRENT_LIST_DIR}/../../plugin")
add_executable(engine-concurrency ../engine-concurrency.cpp "${plugin}/plugin.cpp" "${plugin}/raven.cpp"
               "${plugin}/graph.cpp" "${plugin}/zeek.cpp")
set_source_files_properties("${plugin}/plugin.cpp" PROPERTIES COMPILE_DEFINITIONS RZ_STATIC_API)
target_include_directories(engine-concurrency PRIVATE "${plugin}" "${DEPS}/njson/single_include"
                           "${DEPS}/plugin-sdk/include")
target_link_libraries(engine-concurrency PRIVATE falco_engine Threads::Threads ${CMAKE_DL_LIBS})
