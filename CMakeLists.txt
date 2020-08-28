# CMakeLists.txt - cmake build for liburkel
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/handshake-org/liburkel

set(URKEL_PKG_VERSION 0.0.0)
set(URKEL_ABI_VERSION 0:0:0)

#
# Initialization
#

cmake_minimum_required(VERSION 3.4)
project(liburkel VERSION ${URKEL_PKG_VERSION} LANGUAGES C)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()

#
# Includes
#

include(cmake/AppendCCompilerFlag.cmake)
include(cmake/CheckCThreadLocalStorage.cmake)
include(cmake/TargetLinkOptions.cmake)
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CTest)
include(GNUInstallDirs)

#
# Early Checks
#

set(URKEL_ROOT 0)
set(URKEL_MAKE 0)
set(URKEL_WASM 0)

if(PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)
  set(URKEL_ROOT 1)
endif()

if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
  set(URKEL_MAKE 1)
endif()

check_symbol_exists(__EMSCRIPTEN__ "" URKEL_EMSCRIPTEN)
check_symbol_exists(__wasi__ "" URKEL_WASI)

if(URKEL_EMSCRIPTEN OR URKEL_WASI)
  set(URKEL_WASM 1)
endif()

#
# Options
#

option(URKEL_ENABLE_COVERAGE "Enable coverage" OFF)
option(URKEL_ENABLE_DEBUG "Enable debug build" OFF)

if(URKEL_WASM)
  set(URKEL_INITIAL_MEMORY "16777216" CACHE STRING "WASM initial memory")
  set(URKEL_MAX_MEMORY "2147483648" CACHE STRING "WASM maximum memory")
  set(URKEL_STACK_SIZE "5242880" CACHE STRING "WASM stack size")
endif()

if(URKEL_EMSCRIPTEN)
  set(URKEL_ENVIRONMENT "node" CACHE STRING "Emscripten environment")
endif()

#
# Flags
#

set(urkel_cflags)
set(urkel_ldflags)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 90)

if(NOT URKEL_WASM)
  set(CMAKE_C_VISIBILITY_PRESET hidden)
  set(CMAKE_OSX_DEPLOYMENT_TARGET 10.7)
endif()

if(URKEL_WASI AND CMAKE_C_FLAGS STREQUAL "-v")
  set(CMAKE_C_FLAGS "")
endif()

if(MSVC)
  append_c_compiler_flag(urkel_cflags /wd4146
                                      /wd4244
                                      /wd4267
                                      /wd4334
                                      /wd4996)
else()
  append_c_compiler_flag(urkel_cflags -pedantic
                                      -Wall
                                      -Wextra
                                      -Wcast-align
                                      -Wno-implicit-fallthrough
                                      -Wno-long-long
                                      -Wno-overlength-strings
                                      -Wshadow)
endif()

if(URKEL_ENABLE_COVERAGE)
  list(APPEND urkel_cflags -O0 --coverage)
  list(APPEND urkel_ldflags --coverage)
endif()

if(URKEL_ENABLE_DEBUG)
  if(MSVC)
    append_c_compiler_flag(urkel_cflags /Zi)
  else()
    append_c_compiler_flag(urkel_cflags -g)
  endif()
endif()

#
# Feature Testing
#

if(NOT URKEL_WASM)
  set(THREADS_PREFER_PTHREAD_FLAG ON)

  find_package(Threads REQUIRED)

  if(NOT WIN32 AND NOT CMAKE_USE_PTHREADS_INIT)
    message(FATAL_ERROR "pthread not found")
  endif()
endif()

check_c_thread_local_storage(URKEL_TLS)

#
# Defines
#

set(urkel_defines)

if(WIN32 AND NOT URKEL_WASM)
  list(APPEND urkel_defines _WIN32_WINNT=0x0501)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT URKEL_WASM)
  list(APPEND urkel_defines _POSIX_C_SOURCE=200112)
endif()

if(URKEL_ENABLE_COVERAGE)
  list(APPEND urkel_defines URKEL_COVERAGE)
endif()

if(URKEL_ENABLE_DEBUG)
  list(APPEND urkel_defines URKEL_DEBUG)
else()
  list(APPEND urkel_defines $<$<CONFIG:Debug>:URKEL_DEBUG>)
endif()

if(URKEL_TLS)
  list(APPEND urkel_defines URKEL_TLS=${URKEL_TLS})
endif()

#
# Targets
#

set(urkel_sources src/bits.c
                  src/blake2b.c
                  src/internal.c
                  src/io.c
                  src/nodes.c
                  src/proof.c
                  src/store.c
                  src/tree.c
                  src/util.c)

set(urkel_includes ${PROJECT_SOURCE_DIR}/include)

set(bin_sources src/urkel.c)
set(test_sources test/test.c test/utils.c)
set(bench_sources test/bench.c test/hrtime.c test/utils.c)

if(URKEL_WASM)
  if(URKEL_EMSCRIPTEN)
    # CMAKE_CROSSCOMPILING_EMULATOR is mistakenly quoted by emcmake.
    string(REPLACE "\"" "" CMAKE_CROSSCOMPILING_EMULATOR
           "${CMAKE_CROSSCOMPILING_EMULATOR}")

    # In the future we should set `-s NODERAWFS=1`.
    # For now, the node.js filesystem backend is broken:
    # https://github.com/emscripten-core/emscripten/issues/7487
    set(urkel_ldflags "SHELL:-s SINGLE_FILE=1"
                      "SHELL:-s ASSERTIONS=0"
                      "SHELL:-s NODEJS_CATCH_EXIT=0"
                      "SHELL:-s NODEJS_CATCH_REJECTION=0"
                      "SHELL:-s ALLOW_MEMORY_GROWTH=1"
                      "SHELL:-s INITIAL_MEMORY=${URKEL_INITIAL_MEMORY}"
                      "SHELL:-s MAXIMUM_MEMORY=${URKEL_MAX_MEMORY}"
                      "SHELL:-s TOTAL_STACK=${URKEL_STACK_SIZE}"
                      "SHELL:-s ENVIRONMENT=${URKEL_ENVIRONMENT}")

    set(urkel_sources_lib "")
    set(urkel_ldflags_lib "SHELL:-s EXPORTED_FUNCTIONS=@etc/exports.json")
  else()
    set(CMAKE_EXECUTABLE_SUFFIX ".wasm")

    set(urkel_ldflags -Wl,--allow-undefined
                      -Wl,--initial-memory=${URKEL_INITIAL_MEMORY}
                      -Wl,--max-memory=${URKEL_MAX_MEMORY}
                      -Wl,-z -Wl,stack-size=${URKEL_STACK_SIZE}
                      -Wl,--stack-first)

    # Note: We have to manually choose crt1-reactor.o
    # until reactor support is widely available via:
    #
    #   -mexec-model=reactor
    #
    # See: https://github.com/llvm/llvm-project/commit/d496437
    #      https://reviews.llvm.org/D62922
    set(urkel_syslib ${CMAKE_SYSROOT}/lib/${CMAKE_C_COMPILER_TARGET})
    set(urkel_sources_lib ${urkel_syslib}/crt1-reactor.o)
    set(urkel_ldflags_lib -nostartfiles
                          -Wl,--entry=_initialize
                          -Wl,--export-dynamic
                          -Wl,--export=malloc
                          -Wl,--export=free)
  endif()

  add_library(urkel_o OBJECT ${urkel_sources})
  target_compile_definitions(urkel_o PUBLIC ${urkel_defines}
                                     PRIVATE URKEL_BUILD)
  target_compile_options(urkel_o PUBLIC ${urkel_cflags})
  target_include_directories(urkel_o PUBLIC ${urkel_includes})
  target_link_options(urkel_o INTERFACE ${urkel_ldflags})

  add_executable(urkel ${urkel_sources_lib})
  target_link_options(urkel PRIVATE ${urkel_ldflags_lib})
  target_link_libraries(urkel PRIVATE urkel_o)

  if(BUILD_TESTING)
    add_executable(urkel_bench ${bench_sources})
    target_link_libraries(urkel_bench PRIVATE urkel_o)

    add_executable(urkel_test ${test_sources})
    target_link_libraries(urkel_test PRIVATE urkel_o)
    add_test(NAME test_wasm COMMAND urkel_test)

    if(URKEL_ROOT AND URKEL_MAKE)
      add_custom_target(bench COMMAND urkel_bench)
      add_custom_target(check COMMAND ${CMAKE_MAKE_PROGRAM} test)
    endif()
  endif()
else()
  add_library(urkel_o OBJECT ${urkel_sources})
  target_compile_definitions(urkel_o PRIVATE ${urkel_defines} URKEL_BUILD)
  target_compile_options(urkel_o PRIVATE ${urkel_cflags})
  target_include_directories(urkel_o PRIVATE ${urkel_includes})
  set_property(TARGET urkel_o PROPERTY POSITION_INDEPENDENT_CODE ON)

  add_library(urkel SHARED $<TARGET_OBJECTS:urkel_o>)
  target_compile_definitions(urkel INTERFACE ${urkel_defines})
  target_compile_options(urkel INTERFACE ${urkel_cflags})
  target_include_directories(urkel INTERFACE ${urkel_includes})
  target_link_options(urkel PUBLIC ${urkel_ldflags})
  target_link_libraries(urkel PRIVATE Threads::Threads)

  add_library(urkel_static STATIC $<TARGET_OBJECTS:urkel_o>)
  target_compile_definitions(urkel_static INTERFACE ${urkel_defines})
  target_compile_options(urkel_static INTERFACE ${urkel_cflags})
  target_include_directories(urkel_static INTERFACE ${urkel_includes})
  target_link_options(urkel_static INTERFACE ${urkel_ldflags})
  target_link_libraries(urkel_static INTERFACE Threads::Threads)

  add_executable(urkel_bin ${bin_sources})
  target_link_libraries(urkel_bin PRIVATE urkel)
  set_target_properties(urkel_bin PROPERTIES OUTPUT_NAME urkel)

  if(UNIX)
    string(REPLACE ":" "." urkel_version "${URKEL_ABI_VERSION}")
    string(REGEX MATCH "^[0-9]+" urkel_soversion "${URKEL_ABI_VERSION}")

    set_target_properties(urkel PROPERTIES VERSION ${urkel_version}
                                             SOVERSION ${urkel_soversion})
    set_target_properties(urkel_static PROPERTIES OUTPUT_NAME urkel)

    configure_file(liburkel.pc.in liburkel.pc @ONLY)

    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(FILES LICENSE
            DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/${PROJECT_NAME})
    install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
    install(FILES ${PROJECT_BINARY_DIR}/liburkel.pc
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
    install(TARGETS urkel urkel_static urkel_bin
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  endif()

  if(WIN32)
    install(DIRECTORY include/ DESTINATION include)
    install(FILES LICENSE README.md DESTINATION .)
    install(TARGETS urkel urkel_static urkel_bin
            RUNTIME DESTINATION lib/$<CONFIG>
            ARCHIVE DESTINATION lib/$<CONFIG>)
  endif()

  if(BUILD_TESTING)
    add_executable(urkel_bench ${bench_sources})
    target_link_libraries(urkel_bench PRIVATE urkel)

    add_executable(urkel_test ${test_sources})
    target_link_libraries(urkel_test PRIVATE urkel)
    add_test(NAME test_shared COMMAND urkel_test)

    add_executable(urkel_test_static ${test_sources})
    target_link_libraries(urkel_test_static PRIVATE urkel_static)
    add_test(NAME test_static COMMAND urkel_test_static)

    find_program(URKEL_VALGRIND valgrind)

    if(URKEL_VALGRIND)
      add_test(NAME test_valgrind COMMAND ${URKEL_VALGRIND}
                                          --leak-check=full
                                          --error-exitcode=1
                                          $<TARGET_FILE:urkel_test>)
    endif()

    if(URKEL_ROOT AND URKEL_MAKE)
      add_custom_target(bench COMMAND urkel_bench)
      add_custom_target(check COMMAND ${CMAKE_MAKE_PROGRAM} test)

      if(URKEL_VALGRIND)
        add_custom_target(valgrind COMMAND ${URKEL_VALGRIND}
                                           --leak-check=full
                                           --error-exitcode=1
                                           $<TARGET_FILE:urkel_test>
                                   DEPENDS urkel_test)
      endif()
    endif()
  endif()
endif()

#
# Output
#

string(TOUPPER "${CMAKE_BUILD_TYPE}" urkel_build_type)

message(STATUS "Build Options:

   CMAKE_BUILD_TYPE:     ${CMAKE_BUILD_TYPE}
   CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}
   CMAKE_SYSTEM_NAME:    ${CMAKE_SYSTEM_NAME}
   CMAKE_C_COMPILER:     ${CMAKE_C_COMPILER}
   CMAKE_C_FLAGS:        ${CMAKE_C_FLAGS_${urkel_build_type}} ${CMAKE_C_FLAGS}
   urkel_cflags:         ${urkel_cflags}
   urkel_ldflags:        ${urkel_ldflags}
   urkel_defines:        ${urkel_defines}
")
