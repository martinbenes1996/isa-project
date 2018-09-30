
#include <pcap/pcap.h>

// inspired by http://www.tcpdump.org/pcap.html

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
            if(mhandle == NULL) printErrorAndExit(errbuf, 2);

            status = pcap_set_promisc(mhandle, 1); // set promiscuous mode
            if(status) printErrorAndExit(status, 3);

            status = pcap_activate(mhandle); // activate handle
            if(status) printErrorAndExit(status, 4);
        }

        /**
         * @brief Destructor.
         */
        ~Device() { pcap_close(handle); }

    private:
        pcap_t *mhandle; /**< Handle. */
};

class Sniffer {
    public:
        Sniffer(std::string ifce) {
            char errbuf[PCAP_ERRBUF_SIZE];
            int status;

            // get ip and mask
            bpf_u_int32 mask, ip;
            status = pcap_lookupnet(ifce, &ip, &mask, errbuff);
            if(status == -1) {
                std::cerr << errbuf << "\n";
                ip = mask = 0;
            }

            // open session
            mhandle = pcap_open_live(ifce, BUFSIZ, true, 1000, errbuf);
            if(mhandle == NULL) printErrorAndExit(errbuf, 2);

            // compile filter
            char netexpr[] = "port 520 or 521";
            status = pcap_compile(mhandle, &mfilter, netexpr, 0, ip);
            if(status == -1) printErrorAndExit(errbuf, 3);

            // set filter onto sniffer
            status = pcap_setfilter(mhandle, &mfilter);
            if(status == -1) printErrorAndExit(pcap_geterr(mhandle), 3);
        }

        /**
         * @brief Destructor
         */
        ~Sniffer() { pcap_close(mhandle); }
    private:
        pcap_t *handle;
        struct bpf_program mfilter;
}