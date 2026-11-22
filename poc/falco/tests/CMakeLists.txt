# Open Enclave disables RPATH in the parent directory.
set(CMAKE_SKIP_RPATH FALSE)
add_executable(replay-detector EXCLUDE_FROM_ALL replay-detector.cpp)
set_target_properties(replay-detector PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    BUILD_RPATH_USE_ORIGIN TRUE)
target_include_directories(replay-detector PRIVATE ../plugin "${DEPS}/njson/single_include")
target_link_libraries(replay-detector PRIVATE raven_zeek)
