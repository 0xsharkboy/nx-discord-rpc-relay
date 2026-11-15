#include <iostream>

#include "version.hpp"

int main() {
    std::cout << "relay " << relay::version() << "\n";
    return 0;
}
