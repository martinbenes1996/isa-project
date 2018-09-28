
#include <iostream>
#include <cstring>

char * ifce;

int main(int argc, char *argv[]) {
    if(argc == 3 && !strcmp(argv[1], "-i") ) {
        ifce = argv[2];
    } 
    else {
        std::cerr << "Usage: ./myripsniffer -i <interface>\n";
        exit(1);
    }

    std::cout << "Interface: " << ifce << "\n";
    return 0;
}