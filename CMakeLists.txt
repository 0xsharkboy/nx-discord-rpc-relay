cmake_minimum_required(VERSION 3.25)
project(relay VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra)

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
find_package(OpenSSL REQUIRED)

set(HTTPLIB_REQUIRE_OPENSSL ON)
set(HTTPLIB_COMPILE OFF)
set(DOCTEST_NO_INSTALL ON)
set(JSON_Install OFF)
FetchContent_MakeAvailable(doctest nlohmann_json httplib stb)

add_library(stb INTERFACE)
target_include_directories(stb SYSTEM INTERFACE ${stb_SOURCE_DIR})

set(SDK_DIR ${CMAKE_SOURCE_DIR}/third_party/discord_social_sdk)
add_library(discord_sdk SHARED IMPORTED)
set_target_properties(discord_sdk PROPERTIES
    IMPORTED_LOCATION ${SDK_DIR}/lib/release/libdiscord_partner_sdk.so
    IMPORTED_NO_SONAME ON
    INTERFACE_INCLUDE_DIRECTORIES ${SDK_DIR}/include)

add_library(relay_core STATIC
    src/version.cpp
    src/config.cpp
    src/crypto.cpp
    src/db.cpp
)
target_include_directories(relay_core PUBLIC src)
target_link_libraries(relay_core PUBLIC
    nlohmann_json::nlohmann_json httplib::httplib SQLite3::SQLite3 OpenSSL::SSL OpenSSL::Crypto stb)

add_executable(relay
    src/main.cpp
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
