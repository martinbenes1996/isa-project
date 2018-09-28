
#include <iostream>
#include <cstring>
#include <string>
#include <pcap/pcap.h>

/* ------------------------------ */
char * ifce; /**< Interface name. */
/* ------------------------------ */

/**
 * @brief Prints error and exits.
 * @param error         PCAP error code.
 * @param errcode       Error code.
 */
void printErrorAndExit(int error, int errcode) {
    std::cerr << pcap_statustostr(error) << "\n";
    exit(errcode);
}
/**
 * @brief Prints error and exits.
 * @param error         String to print.
 * @param errcode       Error code.
 */
void printErrorAndExit(std::string error, int errcode) {
    std::cerr << error << "\n";
    exit(errcode);
}

/**
 * @brief Cover class for PCAP library.
 */
class Device {
    public:
        /**
         * @brief Constructor.
         * @param ifce      Interface.
         */
        Device(std::string ifce) {
            char errbuf[PCAP_ERRBUF_SIZE];
            int status;

            handle = pcap_create(ifce.c_str(), errbuf); // create handle
            if(handle == NULL) printErrorAndExit(errbuf, 2);

            status = pcap_set_promisc(handle, 1); // set promiscuous mode
            if(status) printErrorAndExit(status, 3);

            status = pcap_activate(handle); // activate handle
            if(status) printErrorAndExit(status, 4);
        }

        /**
         * @brief Destructor.
         */
        ~Device() { pcap_close(handle); }

    private:
        pcap_t *handle; /**< Handle. */
};

/**
 * @brief   Main function.
 * @param argc          Count of arguments.
 * @param argv          Arguments.
 * @returns Exit code. 
 */
int main(int argc, char *argv[]) {
    
    // -i
    if(argc == 3 && !strcmp(argv[1], "-i") ) {
        ifce = argv[2];
    } 
    // other - fail
    else printErrorAndExit("Usage: ./myripsniffer -i <interface>\n", 1);

    // connect to device
    Device d(ifce);
    
    // Listen
    // ...

    return 0;
}