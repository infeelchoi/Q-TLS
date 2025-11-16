cmake_minimum_required(VERSION 3.15)
project(QTLS VERSION 1.0.0 LANGUAGES C CXX)

# Set C/C++ standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Project options
option(ENABLE_HSM "Enable Luna HSM support via PKCS#11" OFF)
option(ENABLE_TESTS "Build test suite" ON)
option(ENABLE_EXAMPLES "Build example programs" ON)
option(FIPS_MODE "Enable FIPS 140-2 compliant mode" OFF)
option(ENABLE_LOGGING "Enable detailed logging" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")

# Security hardening flags
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security -Werror=format-security")
endif()

# Position independent code for shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find required packages
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Threads REQUIRED)

# Find liboqs (Open Quantum Safe)
find_library(LIBOQS_LIBRARY NAMES oqs liboqs PATHS /usr/local/lib /usr/lib)
find_path(LIBOQS_INCLUDE_DIR NAMES oqs/oqs.h PATHS /usr/local/include /usr/include)

if(NOT LIBOQS_LIBRARY OR NOT LIBOQS_INCLUDE_DIR)
    message(FATAL_ERROR "liboqs not found. Please install from https://github.com/open-quantum-safe/liboqs")
endif()

message(STATUS "Found liboqs: ${LIBOQS_LIBRARY}")
message(STATUS "liboqs include dir: ${LIBOQS_INCLUDE_DIR}")

# PKCS#11 for HSM support
if(ENABLE_HSM)
    find_path(PKCS11_INCLUDE_DIR NAMES pkcs11.h
              PATHS /usr/include /usr/local/include
              PATH_SUFFIXES pkcs11)

    if(NOT PKCS11_INCLUDE_DIR)
        message(WARNING "PKCS#11 headers not found. HSM support may be limited.")
    endif()

    add_definitions(-DENABLE_HSM)
    message(STATUS "Luna HSM support enabled")
endif()

# FIPS mode
if(FIPS_MODE)
    add_definitions(-DFIPS_MODE)
    message(STATUS "FIPS 140-2 mode enabled")
endif()

# Logging
if(ENABLE_LOGGING)
    add_definitions(-DENABLE_LOGGING)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${LIBOQS_INCLUDE_DIR}
)

if(ENABLE_HSM AND PKCS11_INCLUDE_DIR)
    include_directories(${PKCS11_INCLUDE_DIR})
endif()

# Source files
set(QTLS_SOURCES
    # Crypto module
    src/crypto/pqc_crypto.c

    # Protocol module
    src/protocol/handshake.c

    # Server module
    src/server/qtls_server.c

    # Client module
    src/client/qtls_client.c
)

# Create static library
add_library(qtls_static STATIC ${QTLS_SOURCES})
set_target_properties(qtls_static PROPERTIES OUTPUT_NAME qtls)
target_link_libraries(qtls_static
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LIBOQS_LIBRARY}
    Threads::Threads
    m
)

# Create shared library
if(BUILD_SHARED_LIBS)
    add_library(qtls_shared SHARED ${QTLS_SOURCES})
    set_target_properties(qtls_shared PROPERTIES
        OUTPUT_NAME qtls
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
    )
    target_link_libraries(qtls_shared
        OpenSSL::SSL
        OpenSSL::Crypto
        ${LIBOQS_LIBRARY}
        Threads::Threads
        m
    )
endif()

# Add PKCS#11 library if HSM is enabled
if(ENABLE_HSM)
    # Link with dl for dynamic loading of PKCS#11 library
    target_link_libraries(qtls_static dl)
    if(BUILD_SHARED_LIBS)
        target_link_libraries(qtls_shared dl)
    endif()
endif()

# Install targets
install(TARGETS qtls_static
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

if(BUILD_SHARED_LIBS)
    install(TARGETS qtls_shared
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
    )
endif()

# Install headers
install(DIRECTORY include/qtls
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/qtls.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/qtls.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/qtls.pc
    DESTINATION lib/pkgconfig
)

# Examples
if(ENABLE_EXAMPLES)
    add_subdirectory(examples)
endif()

# Tests
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        @ONLY
    )
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
endif()

# Uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)

# Print configuration summary
message(STATUS "")
message(STATUS "Q-TLS Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C Flags: ${CMAKE_C_FLAGS}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  HSM Support: ${ENABLE_HSM}")
message(STATUS "  FIPS Mode: ${FIPS_MODE}")
message(STATUS "  Logging: ${ENABLE_LOGGING}")
message(STATUS "  Tests: ${ENABLE_TESTS}")
message(STATUS "  Examples: ${ENABLE_EXAMPLES}")
message(STATUS "  Shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "  liboqs: ${LIBOQS_LIBRARY}")
message(STATUS "")
