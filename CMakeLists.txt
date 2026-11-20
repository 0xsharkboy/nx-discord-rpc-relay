cmake_minimum_required(VERSION 3.25)
project(relay VERSION 0.1.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra)

# The Discord Social SDK is proprietary and not part of this repository: see docs/self-hosting.md.
set(DISCORD_SDK_DIR ${CMAKE_SOURCE_DIR}/third_party/discord_social_sdk
    CACHE PATH "Directory holding the Discord Social SDK (include/ and lib/release/)")
set(SDK_DIR ${DISCORD_SDK_DIR})
if(NOT EXISTS ${SDK_DIR}/include/discordpp.h OR NOT EXISTS ${SDK_DIR}/lib/release/libdiscord_partner_sdk.so)
    message(FATAL_ERROR "Discord Social SDK not found in ${SDK_DIR}: see docs/self-hosting.md")
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
FetchContent_Declare(doctest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG v2.4.11
    GIT_SHALLOW ON)
FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW ON)
FetchContent_Declare(stb
    GIT_REPOSITORY https://github.com/nothings/stb.git
    GIT_TAG 9600522de53973336fa033a289858a4354cbb04c)
FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.18.7
    GIT_SHALLOW ON)

find_package(SQLite3 REQUIRED)
# CMake before 4.3 (Ubuntu 24.04 ships 3.28) names the imported target SQLite::SQLite3 only.
if(NOT TARGET SQLite3::SQLite3)
    add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
endif()
find_package(OpenSSL REQUIRED)

set(HTTPLIB_REQUIRE_OPENSSL ON)
set(HTTPLIB_COMPILE OFF)
# Decompressed request bodies would bypass the wire payload limit.
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(DOCTEST_NO_INSTALL ON)
set(JSON_Install OFF)
FetchContent_MakeAvailable(doctest nlohmann_json httplib stb)

add_library(stb INTERFACE)
target_include_directories(stb SYSTEM INTERFACE ${stb_SOURCE_DIR})

add_library(discord_sdk SHARED IMPORTED)
set_target_properties(discord_sdk PROPERTIES
    IMPORTED_LOCATION ${SDK_DIR}/lib/release/libdiscord_partner_sdk.so
    INTERFACE_INCLUDE_DIRECTORIES ${SDK_DIR}/include)

# The badge shown next to presences (GET /badge.png) is compiled in, so the image needs no data file.
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/src/assets/badge.png BADGE_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," BADGE_BYTES "${BADGE_HEX}")
# Written to a temporary file and copied only when it changed, so a reconfigure does not rebuild it.
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/generated/badge_png.cpp.tmp
    "// Generated from src/assets/badge.png.\n#include \"badge_png.hpp\"\nnamespace relay {\nconst unsigned char kBadgePng[] = {${BADGE_BYTES}};\nconst std::size_t kBadgePngSize = sizeof(kBadgePng);\n}  // namespace relay\n")
file(COPY_FILE ${CMAKE_CURRENT_BINARY_DIR}/generated/badge_png.cpp.tmp ${CMAKE_CURRENT_BINARY_DIR}/generated/badge_png.cpp
     ONLY_IF_DIFFERENT)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/assets/badge.png)

add_library(relay_core STATIC
    ${CMAKE_CURRENT_BINARY_DIR}/generated/badge_png.cpp
    src/version.cpp
    src/client_version.cpp
    src/config.cpp
    src/crypto.cpp
    src/db.cpp
    src/icon_store.cpp
    src/icons.cpp
    src/links.cpp
    src/oauth.cpp
    src/presence.cpp
    src/refresher.cpp
    src/refusals.cpp
    src/rate_limit.cpp
    src/api.cpp
    src/stb_impl.cpp
)
target_include_directories(relay_core PUBLIC src)
# A burst of consoles reconnecting together overflows cpp-httplib's default accept queue of 5, and
# dropped SYNs are retried by clients after 1 s and 3 s. PUBLIC so that every translation unit that
# includes httplib.h agrees on the inline listen code. The kernel caps it at net.core.somaxconn.
target_compile_definitions(relay_core PUBLIC CPPHTTPLIB_LISTEN_BACKLOG=1024)
target_link_libraries(relay_core PUBLIC
    nlohmann_json::nlohmann_json httplib::httplib SQLite3::SQLite3 OpenSSL::SSL OpenSSL::Crypto stb)

add_executable(relay
    src/main.cpp
    src/sdk_backend.cpp
)
target_link_libraries(relay PRIVATE relay_core discord_sdk)
set_target_properties(relay PROPERTIES
    BUILD_RPATH "$ORIGIN"
    INSTALL_RPATH "$ORIGIN")
add_custom_command(TARGET relay POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${SDK_DIR}/lib/release/libdiscord_partner_sdk.so $<TARGET_FILE_DIR:relay>)

enable_testing()
add_subdirectory(tests)
