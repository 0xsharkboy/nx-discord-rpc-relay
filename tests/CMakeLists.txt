add_executable(relay_tests
    main.cpp
    config_test.cpp
    client_version_test.cpp
    crypto_test.cpp
    db_test.cpp
    icons_test.cpp
    links_test.cpp
    oauth_test.cpp
    presence_test.cpp
    refresher_test.cpp
    rate_limit_test.cpp
    refusals_test.cpp
    api_test.cpp
)
target_link_libraries(relay_tests PRIVATE relay_core doctest::doctest)
add_test(NAME relay_tests COMMAND relay_tests)
