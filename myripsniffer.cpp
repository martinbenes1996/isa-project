
#include <iostream>
#include <cstring>
#include <string>
#include <pcap/pcap.h>

char * ifce;

void printErrorAndExit(int error, int errcode) {
    std::cerr << pcap_statustostr(error) << "\n";
    exit(errcode);
}
void printErrorAndExit(std::string error, int errcode) {
    std::cerr << error << "\n";
    exit(errcode);
}

class Device {
    public:
        Device(std::string ifce) {
            char errbuf[PCAP_ERRBUF_SIZE];
            int status;

            handle = pcap_create(ifce.c_str(), errbuf);
            if(handle == NULL) printErrorAndExit(errbuf, 2);

            status = pcap_set_promisc(handle, 1);
            if(status) printErrorAndExit(status, 3);

            status = pcap_activate(handle);
            if(status) printErrorAndExit(status, 4);
        }

        ~Device() {
            pcap_close(handle);
        }
    private:
        pcap_t *handle;
};


int main(int argc, char *argv[]) {
    if(argc == 3 && !strcmp(argv[1], "-i") ) {
        ifce = argv[2];
    } 
    else printErrorAndExit("Usage: ./myripsniffer -i <interface>\n", 1);

    Device d(ifce);
    
    



    return 0;
}