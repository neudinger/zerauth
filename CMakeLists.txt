cmake_minimum_required(VERSION 3.30)
cmake_host_system_information(RESULT Ncpu QUERY NUMBER_OF_PHYSICAL_CORES)
# Define a job pool named "link_pool" with a maximum of 2 jobs
set_property(GLOBAL PROPERTY JOB_POOLS link_pool=${LINK_JOB_POOLS})
option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
option(CMAKE_COMPILE_WARNING_AS_ERROR "CMAKE_COMPILE_WARNING_AS_ERROR" ON)
option(CMAKE_INCLUDE_CURRENT_DIR "CMAKE_INCLUDE_CURRENT_DIR" ON)

set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
set(BUILD_SHARED_LIBS OFF)

# if("$ENV{zerauth_version}" STREQUAL "") message(WARNING "Setup zerauth_version
# in your environment variable") set(zerauth_version "0.0.0.0") else()
# set(zerauth_version $ENV{zerauth_version}) endif("$ENV{zerauth_version}"
# STREQUAL "")

project(
  zerauth
  LANGUAGES CXX
  DESCRIPTION
    "Non-Interactive Zero-Knowledge Proof with Discrete Logarithm Equality across groups Extended "
  HOMEPAGE_URL "https://github.com/neudinger/zerauth"
  VERSION ${zerauth_version})

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

if(CMAKE_SYSTEM_NAME STREQUAL Emscripten)
  set(CMAKE_EXECUTABLE_SUFFIX .js)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)

  # set(CMAKE_BUILD_TYPE RelWithDebInfo)

  # remove_definitions(NDEBUG)

  # add_compile_definitions(NDEBUG=1)

  # set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(FlatBuffers CONFIG REQUIRED)
find_program(CPPCHECK_EXE NAMES cppcheck REQUIRED)
find_program(CLANG_FORMAT NAMES clang-format REQUIRED)
find_program(CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
find_program(CPP_LINT NAMES cpplint REQUIRED)
find_program(INFER NAMES infer REQUIRED)
find_program(PMD NAMES pmd REQUIRED)
option(CCACHE "Activation of CCACHE" ON)
find_program(FLATBUFFER_FLATC NAMES flatc)

if(CCACHE)
  find_program(CCACHE_PROGRAM NAMES ccache REQUIRED)
  set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif(CCACHE)

# find_package(OpenSSL 3.5.2 REQUIRED)
find_package(Threads REQUIRED)

set(ROOT_DIR ${CMAKE_SOURCE_DIR})
list(APPEND CMAKE_MODULE_PATH ${ROOT_DIR}/cmake
     ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

cmake_path(APPEND FLATBUFFER_PATH ${CMAKE_CURRENT_LIST_DIR} flatb)
cmake_path(APPEND SRC_PATH ${PROJECT_SOURCE_DIR} src)

include(FlatBuffGen)

file(GLOB_RECURSE SRCS ${SRC_PATH}/*.cpp)
include_directories(${PROJECT_SOURCE_DIR} ${SRC_PATH})
add_executable(${PROJECT_NAME} ${SRCS})

# https://clang.llvm.org/extra/clang-tidy/ -p ${CMAKE_SOURCE_DIR}
# --config-file=${CMAKE_SOURCE_DIR} --enable-module-headers-parsing
# --explain-config

set(CLANG_TIDY_COMMAND ${CLANG_TIDY_EXE}
                       --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy)

# https://github.com/StableCoder/cmake-scripts/blob/main/tools.cmake
# https://gist.github.com/bjornblissing/60c2d425532e6dd534841a8d1d2ffe76
set(CPPCHECK_OPTS
    --language=c++
    --std=c++20
    -D__cplusplus=202002L
    --verbose
    --enable=all
    -I
    /usr/local/include
    --check-level=exhaustive
    --suppress=unmatchedSuppression
    --library=std
    --library=posix
    --inline-suppr # // cppcheck-suppress preprocessorErrorDirective
    --cppcheck-build-dir=${CMAKE_CURRENT_BINARY_DIR}
    --suppressions-list=${CMAKE_CURRENT_SOURCE_DIR}/cppcheck-suppressions-list.txt
    --checkers-report=${CMAKE_CURRENT_BINARY_DIR}/cppcheck_report.txt
    --project=${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json)

add_custom_command(
  OUTPUT CPPCHECK
  COMMAND
    ${CMAKE_COMMAND} -E echo "Running cppchecker..." && ${CMAKE_COMMAND} -E echo
    "${CPPCHECK_EXE} ${CPPCHECK_OPTS}" && ${CPPCHECK_EXE} ${CPPCHECK_OPTS} 2>
    ${CMAKE_CURRENT_BINARY_DIR}/cppcheck_errors.txt && ${CMAKE_COMMAND} -E echo
    "cppchecker end."
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Running Cppcheck static analysis"
  VERBATIM)

# add_custom_target(cppcheck ALL DEPENDS CPPCHECK)

add_custom_target(
  clang_format
  COMMAND
    ${CLANG_FORMAT} --Werror --verbose
    --style=file:${CMAKE_CURRENT_LIST_DIR}/.clang-format -i ${SRCS}
    ${PROTOS_SERVICES_IMPL_SRCS})

add_custom_target(
  cpplint
  COMMAND
    ${CMAKE_COMMAND} -E echo "Running ${CPP_LINT}..." && ${CPP_LINT} --verbose=5
    ${SRCS} ${PROTOS_SERVICES_IMPL_SRCS} && ${CMAKE_COMMAND} -E echo
    "${CPP_LINT} check passed."
  COMMENT "Running cpplint on source files..."
  VERBATIM)

# https://fbinfer.com/docs/man-infer-run/ --debug --debug-level 2

add_custom_target(
  infer
  COMMAND
    ${CMAKE_COMMAND} -E echo "Running ${INFER}..." && ${INFER} run --jobs
    ${Ncpu} --fail-on-issue --keep-going --no-debug --force-integration g++
    --results-dir ${CMAKE_CURRENT_SOURCE_DIR}/infer-out --compilation-database
    ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json && ${CMAKE_COMMAND} -E
    echo "${INFER} check passed."
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Running infer on source files..."
  VERBATIM)

# set_target_properties(${PROJECT_NAME} PROPERTIES CXX_CLANG_TIDY
# "${CLANG_TIDY_COMMAND}")
# add_custom_target(cpd COMMAND ${PMD} cpd --verbose --minimum-tokens 200
# --language cpp --file-list ${SRCS}) add_dependencies(${PROJECT_NAME} cppcheck)
# add_dependencies(${PROJECT_NAME} cpplint) add_dependencies(${PROJECT_NAME}
# clang_format) add_dependencies(${PROJECT_NAME} infer)
# add_dependencies(${PROJECT_NAME} cpd)

# emcmake cmake -B build_add_lib && cmake --build build_add_lib emcc -O2 -s
# WASM=1 -s SIDE_MODULE=1 -o add.wasm add.cpp emcc add.cpp -s
# EXPORTED_FUNCTIONS="['_add']" -s SIDE_MODULE=1 -O2 -o add.wasm emcc add.cpp -o
# add.wasm -s WASM=1 -s SIDE_MODULE=1 -O3

# target_compile_options( ${PROJECT_NAME} PRIVATE # Need libsan
# -fsanitize=leak,address -fsanitize=thread # -fsanitize=address
# -fno-omit-frame-pointer -fstack-protector-strong -fno-omit-frame-pointer -Wall
# -Wextra -Wfatal-errors -Wpedantic -Werror -Wshadow -Wdouble-promotion
# -Wformat=2 -Wformat-truncation -Wundef -fno-common -Wno-unknown-pragmas
# -Wno-attributes -Wno-unknown-attributes -Wno-conversion)

include_directories(${PROJECT_NAME} /usr/local/include/
                    /usr/local/openssl/include/)
include_directories(${PROJECT_NAME} ${SRC_PATH}/flatbuffer)
target_link_directories(${PROJECT_NAME} PRIVATE "/opt/lib/")
target_link_directories(${PROJECT_NAME} PRIVATE "/usr/local/lib/")

set_target_properties(
  ${PROJECT_NAME}
  PROPERTIES
    LINKER_LANGUAGE CXX
    LINK_FLAGS
    "-s EXPORT_NAME='${PROJECT_NAME}' -s MODULARIZE=1 -s ALLOW_TABLE_GROWTH -s WASM=1"
    # An executable target is often required to produce a .wasm + .js
    OUTPUT_NAME ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_SEARCH_START_STATIC ON
                                                 LINK_SEARCH_END_STATIC ON)

# if(EMSCRIPTEN OR (CMAKE_CXX_COMPILER_ID STREQUAL "Emscripten"))

target_include_directories(
  ${PROJECT_NAME} BEFORE
  PUBLIC "/usr/local/wasm/include/"
         "/opt/share/emsdk/upstream/emscripten/system/include/")
target_link_directories(${PROJECT_NAME} BEFORE PUBLIC "/usr/local/wasm/lib/")

# else(EMSCRIPTEN OR (CMAKE_CXX_COMPILER_ID STREQUAL "Emscripten"))
# endif(EMSCRIPTEN OR (CMAKE_CXX_COMPILER_ID STREQUAL "Emscripten"))

# add_library(${PROJECT_NAME}_lib STATIC ${PROJECT_NAME}.cpp)

# flatbuffers.a ssl.a crypto.a
target_link_libraries(${PROJECT_NAME} embind
                      /usr/local/wasm/openssl/lib/libcrypto.a)
# target_link_options(${PROJECT_NAME} PRIVATE "-static-libgcc"
# "-static-libstdc++")

# https://cmake.org/cmake/help/latest/prop_gbl/CMAKE_CXX_KNOWN_FEATURES.html
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_${CMAKE_CXX_STANDARD}
                                                cxx_constexpr cxx_decltype)

foreach(FLATBUF_DEP IN LISTS FLATBUF_DEPS)
  add_dependencies(${TARGET_NAME} ${FLATBUF_DEP})
endforeach(FLATBUF_DEP IN LISTS FLATBUF_DEPS)
