add_executable(relay_tests
    main.cpp
    config_test.cpp
    crypto_test.cpp
)
target_link_libraries(relay_tests PRIVATE relay_core doctest::doctest)
add_test(NAME relay_tests COMMAND relay_tests)
