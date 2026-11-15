#include <iostream>

#define DISCORDPP_IMPLEMENTATION
#include "discordpp.h"

#include "version.hpp"

int main() {
    std::cout << "relay " << relay::version() << " (sdk error 0: "
              << discordpp::Client::ErrorToString(discordpp::Client::Error::None) << ")\n";
    return 0;
}
