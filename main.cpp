/****************************************************************************
*
*  Copyright: (c) 2015 Paul Greenberg. All rights reserved.
*
*  This work is licensed under the terms of the MIT license.  
*  For a copy, see <https://opensource.org/licenses/MIT>.
*
****************************************************************************/

#define APP_NAME "mnpa"
#define APP_VER "1.0"
#define APP_DESCR "Multicast Network Performance Analyzer"

#include <regex>
#include <iostream>
#include <cstring>
#include <string>
#include <random>
#include <algorithm>
#include <chrono>
#include <csignal>
#include <thread>
#include <mutex>
#include <cassert>
#include <map>

#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fstream>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>

using namespace std;
using namespace std::chrono;

volatile bool stopped;
std::mutex mu_cout;
std::mutex mu_thrids;
std::mutex mu_rthrids;
bool DAEMONIZE = false;
bool RANDOMIZE = false;
bool IGMP_REPORT_ONLY = false;
bool USE_IGMP_V3 = false;
bool NON_ROOT = false;
bool REQUESTED_STOP = false;
bool REQUESTED_STATUS = false;
bool PACKET_STORM = false;
int VERBOSE = 2;
std::map<long unsigned int,unsigned int> thrids;
std::map<long unsigned int,unsigned int> rthrids;
enum severity { INFO, WARN, ERROR };
const int MAX = 255;
//const int MAX_PAYLOAD_SIZE = 200000;
const int MAX_PAYLOAD_SIZE = 2000;
char rand_pkt_payload[MAX_PAYLOAD_SIZE];
std::random_device rd;
std::mt19937 eng(rd());

struct MulticastSender {
    const char * interface;
    sockaddr_in group;
    unsigned char ttl;
    unsigned int count;
    unsigned int low;
    unsigned int high;
    std::chrono::seconds duration;
    std::chrono::seconds offset;
    std::chrono::microseconds interval;
    std::string tag;
};


struct MulticastReceiver {
    sockaddr_in listener;
    ip_mreq group;
    std::chrono::seconds duration;
};


std::string ipv4_from_s_addr(unsigned long saddr) {
    char ipv4[MAX];
    // The htonl() function converts the unsigned integer hostlong
    // from host byte order to network byte order.
    // The converted value remains unsigned long
    unsigned long ip = htonl(saddr);
    sprintf(ipv4, "%lu.%lu.%lu.%lu", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return string(ipv4);
}


void logit(severity lvl, std::string s) {
    if (VERBOSE == 0) return;
    std::lock_guard<std::mutex> guard(mu_cout);
    switch(lvl) {
        case INFO  : printf("[INFO] %s\n", s.c_str()); break;
        case WARN  : printf("[WARN] %s\n", s.c_str()); break;
        case ERROR : fprintf(stderr, "[ERROR] %s\n", s.c_str()); break;
    }
}


void fill_pkt_payload() {
    std::uniform_int_distribution<> distr(32, 126);
    int i = 0;
    while ( i < MAX_PAYLOAD_SIZE) {
        rand_pkt_payload[i] = static_cast<char>(distr(eng));
        i++;
    }
    //logit(INFO, pktpld);
    //exit(1);
}


void stop() {
    std::string pid_title = "Name:\\tmnpa";
    int pid = -1;
    std::string stop_pid = std::to_string(getpid());
    DIR *dp = opendir("/proc");
    if (dp == NULL) {
        logit(ERROR,"failed to open /proc directory");
        exit(1);
    }
    struct dirent *dir;
    std::vector<pid_t> pids;
    std::regex stop_pid_rgx ("Name:\\tmnpa");
    while (pid < 0 && (dir = readdir(dp))) {
        int cid = atoi(dir->d_name);
        if (cid > 0) {
            std::string cur_pid = std::to_string(cid);
            std::string cur_pid_file = "/proc/" + cur_pid + "/status";
            std::ifstream cid_fs;
            cid_fs.open(cur_pid_file, std::ifstream::in);
            if (cid_fs.is_open()) {
                std::string cur_pid_status;
                getline(cid_fs, cur_pid_status);
                cid_fs.close();
                if (std::regex_match(cur_pid_status, stop_pid_rgx)) {
                    if (stop_pid != cur_pid) {
                        pids.push_back(cid);
                    }
                }
            }
        }
    }
    if (pids.size() > 0) {
        logit(INFO,"mnpa is running, stopping processes ...");
        for (auto &i : pids) {
            kill(i, SIGQUIT);
        }
        sleep(5);
        for (auto &i : pids) {
            if (kill(i, 0) == 0) {
                logit(INFO,"mnpa with PID #" + std::to_string(i) + " is still running!");
            } else {
                logit(INFO,"mnpa with PID #" + std::to_string(i) + " was stopped successfully");
            }
        }
    } else {
        logit(INFO,"mnpa is not running ...");
    }
    closedir(dp);
    return;
}


void help(int code) {
    cout << endl;
    cout << APP_NAME << " - " << APP_DESCR << endl;
    cout << endl;
    cout << "usage: " << APP_NAME << " [-h] [-d] [--sender PATTERN] ";
    cout << "[--sender PATTERN] [--receiver PATTERN] [--threads THREADS]" << endl;
    cout << endl;
    cout << "examples:" << endl;
    cout << endl;
    cout << "  " << APP_NAME << " --threads 5 --sender ";
    cout << "eth1/1000/64-127/0/0/239.1.2.4/5001/TEST1 --verbose" << endl;
    cout << "  " << APP_NAME << " --threads 5 ";
    cout << "--sender eth1/5/64-128/60/0/224.0.0.1/5001/TEST2 ";
    cout << "--sender eth1/5/64-128/60/0/224.0.0.1/5001/TEST3" << endl;
    cout << "  " << APP_NAME << " --threads 1 ";
    cout << "--receiver 10.254.0.12/239.1.1.1/5001/600" << endl;
    cout << "  " << APP_NAME << " --help" << endl;
    cout << "  " << endl;
    cout << "arguments:" << endl;
    cout << endl;
    cout << "  -s, --sender          sourcing pattern" << endl;
    cout << endl;
    cout << "    A multicast sourcing traffic pattern consists of:" << endl;
    cout << endl;
    cout << "      1. interface name, default: eth0" << endl;
    cout << "      2. number of packets, default: 5" << endl;
    cout << "      3. packet size, e.g. 64, 64-127, 128-255, 300-312" << endl;
    cout << "      4. traffic duration in seconds, default: 2" << endl;
    cout << "      5. thread start offset in seconds, default: 0" << endl;
    cout << "      6. destination ip address, default: 224.0.0.1" << endl;
    cout << "      7. destination port, default: 5001" << endl;
    cout << "      8. traffic tag, default: MNPA" << endl;
    cout << endl;
    cout << "  -r, --receiver      subscription pattern" << endl;
    cout << endl;
    cout << "    A multicast subscription pattern consists of:" << endl;
    cout << endl;
    cout << "      1. interface ip address, e.g 127.0.0.1, or name, e.g. eth1" << endl;
    cout << "      2. multicast group ip address, e.g. 239.1.1.1" << endl;
    cout << "      3. destination port, e.g. 5001" << endl;
    cout << "      4. subscription duration in seconds, default: unlimited (0)" << endl;
    cout << endl;
    cout << "  --igmp-v2-report      send IGMPv2 membership report only" << endl;
    cout << "  --igmp-v3-report      send IGMPv3 membership report only" << endl;
    cout << endl;
    cout << "    The above IGMP v2 or v3 Membership Report switches are used" << endl;
    cout << "    with the --receiver argument. Also, when one of the switches" << endl;
    cout << "    is enabled, the application sends raw membership report packets," << endl;
    cout << "    without responding to membership queries." << endl;
    cout << endl;
    cout << "  -t, --threads         number of concurrent threads, default: 1" << endl;
    cout << "  -p, --priority        program scheduling priority, default: 0" << endl;
    cout << "  -d, --daemonize       run in background, default: disabled" << endl;
    cout << "  -l, --log             enable logging, default: disabled" << endl;
    cout << "  --random-payload      enable payload randomization, default: disabled" << endl;
    cout << "  --packet-storm        send packets w/out waiting for conditions, default: disabled" << endl;
    cout << endl;
    cout << "  --stop                stop service" << endl;
    cout << "  --status              status service" << endl;
    cout << endl;
    cout << "documentation: https://github.com/greenpau/mnpa" <<endl;
    cout << endl;
    exit(code);
}


void signal_handler(int id) {
    if (stopped == true) {
        logit(INFO, "process termination is already in progress. be patient ...");
    } else {
        logit(INFO, "terminated by signal id #" + std::to_string(id));
        stopped = true;
    }
}

std::string format_t(unsigned long long n) {
    std::string s;
    int i = 0;
    do {
        s.insert(0, 1, char('0' + n % 10));
        n /= 10;
        if (++i == 3 && n) {
            s.insert(0, 1, ',');
            i = 0;
        }
    } while (n);
    return s;
}


void regex_error_handler(std::regex_error e) {
    if (e.code() == std::regex_constants::error_collate) {
        logit(ERROR,"regular expression errored std::regex_constants::error_collate");
    } else if (e.code() == std::regex_constants::error_ctype) {
        logit(ERROR,"regular expression errored std::regex_constants::error_ctype");
    } else if (e.code() == std::regex_constants::error_escape) {
        logit(ERROR,"regular expression errored std::regex_constants::error_escape");
    } else if (e.code() == std::regex_constants::error_backref) {
        logit(ERROR,"regular expression errored std::regex_constants::error_backref");
    } else if (e.code() == std::regex_constants::error_brack) {
        logit(ERROR,"regular expression errored std::regex_constants::error_brack");
    } else if (e.code() == std::regex_constants::error_paren) {
        logit(ERROR,"regular expression errored std::regex_constants::error_paren");
    } else if (e.code() == std::regex_constants::error_brace) {
        logit(ERROR,"regular expression errored std::regex_constants::error_brace");
    } else if (e.code() == std::regex_constants::error_badbrace) {
        logit(ERROR,"regular expression errored std::regex_constants::error_badbrace");
    } else if (e.code() == std::regex_constants::error_range) {
        logit(ERROR,"regular expression errored std::regex_constants::error_range");
    } else if (e.code() == std::regex_constants::error_space) {
        logit(ERROR,"regular expression errored std::regex_constants::error_space");
    } else if (e.code() == std::regex_constants::error_badrepeat) {
        logit(ERROR,"regular expression errored std::regex_constants::error_badrepeat");
    } else if (e.code() == std::regex_constants::error_complexity) {
        logit(ERROR,"regular expression errored std::regex_constants::error_complexity");
    } else if (e.code() == std::regex_constants::error_stack) {
        logit(ERROR,"regular expression errored std::regex_constants::error_stack");
    } else {
        logit(ERROR,"regular expression errored with " + std::to_string(e.code()));
    }
}

const char * gen_pkt_payload(size_t& pkt_content_size, std::string& pkt_tag, unsigned long long& pi, unsigned int& psl, unsigned int& psh) {
    size_t ptr_pos = 0;
    char * pkt_content = nullptr;
    // pre-populated fields: 65 chars
    //  * headers:   42 chars, i.e. Ethernet (14 bytes), IP (20 bytes) and UDP (8 bytes)
    //  * timestamp: 20 chars
    //  * separators: 3 chars
    //  * id:         x chars
    //  * tag:        y chars
    std::string pkt_id = std::to_string(pi);
    size_t pkt_header_size = 23 + pkt_id.size() + pkt_tag.size();
    pkt_content_size = pkt_header_size;
    // randomize a packet size
    if (psl != psh) {
        std::uniform_int_distribution<> distr(psl, psh);
        pkt_content_size = distr(eng);
    }
    //printf("pkt_content_size: %zu\n", pkt_content_size);
    //printf("pkt_header_size: %zu\n", pkt_header_size);
    if ((pkt_content_size - pkt_header_size) < 42)  {
        //printf("new pkt_content_size (for header packets only): %zu\n", pkt_content_size);
        pkt_content = new char[pkt_content_size];
    } else {
        pkt_content_size -= 42;
        pkt_content = new char[pkt_content_size];
        memcpy(pkt_content, rand_pkt_payload, pkt_content_size);
        //printf("new pkt_content_size: %zu\n", pkt_content_size);
    }
    // setting the pointer's position to 20, because taking ns timestamp closer to the end of
    // this function improves accuracy of measurements.
    ptr_pos = 20;
    pkt_content[ptr_pos] = ';';
    ptr_pos++;
    pkt_id.copy(pkt_content+ptr_pos, pkt_id.size(), 0);
    ptr_pos += pkt_id.size();
    pkt_content[ptr_pos] = ';';
    ptr_pos++;
    pkt_tag.copy(pkt_content+ptr_pos, pkt_tag.size(), 0);
    ptr_pos += pkt_tag.size();
    pkt_content[ptr_pos] = ';';
    ptr_pos++;
    std::string nts = std::to_string(duration_cast<nanoseconds>(high_resolution_clock::now().time_since_epoch()).count());
    nts.insert(10,".");
    nts.copy(pkt_content, nts.size(), 0);
    return pkt_content;
}


void receiver_thread(struct MulticastReceiver receiver) {

    auto thrid = std::hash<std::thread::id>()(std::this_thread::get_id());

    logit(INFO, "receiver thread #" + std::to_string(thrid) + " / " + \
          ipv4_from_s_addr(receiver.group.imr_multiaddr.s_addr) + ":" + \
          std::to_string(ntohs(receiver.listener.sin_port)) + " / started ...");

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0) {
        logit(ERROR, "receiver thread #" + std::to_string(thrid) + " / " + \
              ipv4_from_s_addr(receiver.group.imr_multiaddr.s_addr) + ":" + \
              std::to_string(ntohs(receiver.listener.sin_port)) + \
              " failed to open a datagram socket");
    }

    int reuse_sock = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse_sock, sizeof(reuse_sock)) < 0) {
        logit(ERROR, "receiver thread #" + std::to_string(thrid) + " / " + \
              ipv4_from_s_addr(receiver.group.imr_multiaddr.s_addr) + ":" + \
              std::to_string(ntohs(receiver.listener.sin_port)) + \
              " failed to set SO_REUSEADDR");
        close(sockfd);
        return;
    }

    if (bind(sockfd, (struct sockaddr*)&receiver.listener, sizeof(receiver.listener))) {
        logit(ERROR, "receiver thread #" + std::to_string(thrid) + " / " + \
              ipv4_from_s_addr(receiver.group.imr_multiaddr.s_addr) + ":" + \
              std::to_string(ntohs(receiver.listener.sin_port)) + \
              " failed to bind a datagram socket");
        close(sockfd);
        return;
    }

    for (;;) {
        if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&receiver.group, sizeof(receiver.group)) < 0) {
            logit(ERROR, "receiver thread #" + std::to_string(thrid) + " / " + \
                  ipv4_from_s_addr(receiver.group.imr_multiaddr.s_addr) + ":" + \
                  std::to_string(ntohs(receiver.listener.sin_port)) + \
                  " failed to inform kernel of multicast group");
            close(sockfd);
            return;
        }
        if (IGMP_REPORT_ONLY == false) {
            break;
        } else {
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
        if (stopped == true) break;
    }

    if (IGMP_REPORT_ONLY == false) {
        auto tp = std::chrono::high_resolution_clock::now() + receiver.duration;
        char rcvbuf[65535];
        while(1) {
            struct sockaddr_storage sender_addr;
            ssize_t read_sz;
            socklen_t sender_addr_len = sizeof(sender_addr);
            memset(&sender_addr, 0, sizeof(struct sockaddr_storage));
            memset(&rcvbuf, 0, 65535);
            read_sz = recvfrom(sockfd, rcvbuf, sizeof(rcvbuf), MSG_DONTWAIT,
                               (struct sockaddr *) &sender_addr, &sender_addr_len);
            /*
            if ( read_sz == -1) {
                logit(ERROR, "receiver thread #" + std::to_string(thrid) + " / " + \
                      ipv4_from_s_addr(receiver.group.imr_multiaddr.s_addr) + ":" + \
                      std::to_string(ntohs(receiver.listener.sin_port)) + \
                      " failed to receive a datagram");
                close(sockfd);
                break;
            }
            */
            if (read_sz > 0) {
                logit(INFO, "receiver thread #" + std::to_string(thrid) + " / " + \
                      ipv4_from_s_addr(receiver.group.imr_multiaddr.s_addr) + ":" + \
                      std::to_string(ntohs(receiver.listener.sin_port)) + \
                      " received: ");
                //printf("received %zd bytes: \"%s\"\n", read_sz, rcvbuf);
            }
            if (stopped == true) break;
            if (std::chrono::high_resolution_clock::now() >= tp) break;
        }
    }
    close(sockfd);
    mu_thrids.lock();
    thrids[thrid] = 1;
    mu_thrids.unlock();
    return;
}


void sender_thread(struct MulticastSender sender) {

    auto thrid = std::hash<std::thread::id>()(std::this_thread::get_id());
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    int msg_ttl_rc;
    msg_ttl_rc = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &sender.ttl, sizeof(sender.ttl));
    if (msg_ttl_rc < 0 && NON_ROOT == false) {
        logit(WARN, "setsockopt IP_MULTICAST_TTL failed on interface" + std::string(sender.interface) + \
                    " for the traffic destined to " + ipv4_from_s_addr(sender.group.sin_addr.s_addr) + \
                    ":" + std::to_string(ntohs(sender.group.sin_port)));
    }

    int msg_if_rc;
    msg_if_rc = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, sender.interface, sizeof(sender.interface));
    if (msg_if_rc < 0 && NON_ROOT == false) {
        logit(WARN,"setsockopt SO_BINDTODEVICE failed on interface " + std::string(sender.interface) + \
                    " for the traffic destined to " + ipv4_from_s_addr(sender.group.sin_addr.s_addr) + \
                    ":" + std::to_string(ntohs(sender.group.sin_port)));
    }

    std::string msg;
    auto tp = std::chrono::high_resolution_clock::now();
    size_t pkt_content_size;
    if (PACKET_STORM == true) {
        for(unsigned long long i=1; i < sender.count + 1; i++) {
            const char *pkt_content = nullptr;
            pkt_content = gen_pkt_payload(std::ref(pkt_content_size), std::ref(sender.tag), std::ref(i), std::ref(sender.low), std::ref(sender.high));
            sendto(sockfd, pkt_content, pkt_content_size, 0, (struct sockaddr *)&sender.group, sizeof(sender.group));
            logit(INFO, std::string("thread #") + std::to_string(thrid) + std::string(" / packet #") + \
                        std::to_string(i) + std::string(" / payload (") + std::to_string(pkt_content_size) + \
                        std::string("): ") + pkt_content);
            delete pkt_content;
        }
    } else if (sender.count == 0) {
        unsigned long long i = 1;
        for (;;) {
            tp = std::chrono::high_resolution_clock::now() + sender.interval;
            const char *pkt_content = nullptr;
            pkt_content = gen_pkt_payload(std::ref(pkt_content_size), std::ref(sender.tag), std::ref(i), std::ref(sender.low), std::ref(sender.high));
            sendto(sockfd, pkt_content, pkt_content_size, 0, (struct sockaddr *)&sender.group, sizeof(sender.group));
            logit(INFO, std::string("thread #") + std::to_string(thrid) + std::string(" / packet #") + \
                        std::to_string(i) + std::string(" / payload (") + std::to_string(pkt_content_size) + \
                        std::string("): ") + pkt_content);
            delete pkt_content;
            i++;
            this_thread::sleep_until(tp);
            if (stopped == true) break;
        }
    } else {
        size_t pkt_content_size;
        for(unsigned long long i=1; i < sender.count + 1; i++) {
            tp = std::chrono::high_resolution_clock::now() + sender.interval;
            const char *pkt_content = nullptr;
            pkt_content = gen_pkt_payload(std::ref(pkt_content_size), std::ref(sender.tag), std::ref(i), std::ref(sender.low), std::ref(sender.high));
            sendto(sockfd, pkt_content, pkt_content_size, 0, (struct sockaddr *)&sender.group, sizeof(sender.group));
            logit(INFO, std::string("thread #") + std::to_string(thrid) + std::string(" / packet #") + \
                        std::to_string(i) + std::string(" / payload (") + std::to_string(pkt_content_size) + \
                        std::string("): ") + pkt_content);
            delete pkt_content;
            this_thread::sleep_until(tp);
            if (stopped == true) break;
        }
    }

    close(sockfd);
    mu_thrids.lock();
    thrids[thrid] = 1;
    mu_thrids.unlock();
    return;
}


void mgr_thread(struct MulticastSender senders[], int cnts, struct MulticastReceiver receivers[], int cntr) {
    volatile bool finished = false;
    std::vector <std::thread> thrs;

    if (cnts > 0) {
        for( int i = 0; i < cnts; i++ ) {
            std::thread thr = std::thread(sender_thread, senders[i]);
            auto thrid = std::hash<std::thread::id>()(thr.get_id());
            thrs.push_back(std::move(thr));
            assert(!thr.joinable());
            mu_thrids.lock();
            thrids[thrid] = 2;
            //logit(INFO,"started sender thread #" + std::to_string(thrid) + " in stage #" + std::to_string(thrids[thrid]));
            mu_thrids.unlock();
        }
    }

    if (cntr > 0) {
        for( int i = 0; i < cntr; i++ ) {
            std::thread thr = std::thread(receiver_thread, receivers[i]);
            auto thrid = std::hash<std::thread::id>()(thr.get_id());
            thrs.push_back(std::move(thr));
            assert(!thr.joinable());
            mu_thrids.lock();
            thrids[thrid] = 2;
            //logit(INFO,"started sender thread #" + std::to_string(thrid) + " in stage #" + std::to_string(thrids[thrid]));
            mu_thrids.unlock();
        }
    }

    do {
        finished = true;
        std::for_each(thrs.begin(), thrs.end(), [&finished](std::thread& thr) {
            auto thrid = std::hash<std::thread::id>()(thr.get_id());
            mu_thrids.lock();
            unsigned int thr_status = thrids[thrid];
            mu_thrids.unlock();
            //logit(INFO, "thread #" + std::to_string(thrid) + " is in stage #" + std::to_string(thr_status));
            if (thr_status != 1) {
                finished = false;
            } else {
                if (thr.joinable() && thr_status == 1) {
                    thr.join();
                }
            }
        });
        sleep(1);
    } while (finished == false);

    if (DAEMONIZE == false) {
        return;
    } else {
        exit(0);
    }
}


int main(int argc, char* argv[]) {

    int thc = 1;
    // define data structure for multicast source threads
    MulticastSender senders[MAX];
    // define counter to store the id of a latest multicast source thread
    int cnts = 0;
    // define data structure for multicast receiver threads
    MulticastReceiver receivers[MAX];
    // define counter to store the id of a latest receiver thread
    int cntr = 0;
    // program scheduling priority
    int thrp = 0;

    if (argc < 2) {
       help(1);
    }

    for(int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            help(0);
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sender") == 0) {
            if (i+1 == argc) {
                logit(ERROR, "failed to supply a value for " + std::string(argv[i]) + " option");
                exit(1);
            }
            try {
                std::string rgx = "(\\S+)/(\\d+)/(\\d+-?\\d+?)/(\\d+)/(\\d+)/(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})/(\\d+)/(\\S+)";
                std::regex tp_rgx(rgx, std::regex_constants::ECMAScript);
                std::regex tp_rgx_range("(\\d+)-(\\d+)");
                std::string ia = argv[i+1];
                std::smatch m_rgx;
                if (std::regex_match(ia, m_rgx, tp_rgx)) {
                    char * ifname = new char [m_rgx[1].length()+1];
                    std::strcpy(ifname, std::string(m_rgx[1]).c_str());
                    senders[cnts].interface = ifname;
                    senders[cnts].count = stoi(m_rgx[2]);
                    std::smatch m_rgx_range;
                    std::string psr = m_rgx[3];
                    if (std::regex_match(psr, m_rgx_range, tp_rgx_range)) {
                        senders[cnts].low = stoi(m_rgx_range[1]);
                        senders[cnts].high = stoi(m_rgx_range[2]);
                    } else {
                        senders[cnts].low = stoi(psr);
                        senders[cnts].high = stoi(psr);
                    }
                    senders[cnts].group.sin_family = AF_INET;
                    senders[cnts].group.sin_addr.s_addr = inet_addr(m_rgx.str(6).c_str());
                    senders[cnts].group.sin_port = htons(stoi(m_rgx[7]));
                    senders[cnts].ttl = 255;
                    senders[cnts].duration = std::chrono::seconds(stoi(m_rgx[4]));
                    senders[cnts].offset = std::chrono::seconds(stoi(m_rgx[5]));
                    senders[cnts].tag = m_rgx[8];
                    if (senders[cnts].count == 0) {
                        senders[cnts].interval = std::chrono::microseconds(stoi(m_rgx[4]));
                    } else {
                        senders[cnts].interval = std::chrono::duration_cast<std::chrono::microseconds>(senders[cnts].duration) / senders[cnts].count;
                    }
                    cnts++;
                } else {
                    logit(ERROR, "failed to provide a valid multicast sender traffic pattern via " + \
                          std::string(argv[i]) + ": " + ia);
                    exit(1);
                }
            } catch (std::regex_error& e) {
                regex_error_handler(e);
                exit(1);
            }
            i++;
        } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--receiver") == 0) {
            if (i+1 == argc) {
                logit(ERROR, "failed to supply a value for " + std::string(argv[i]) + " option");
                exit(1);
            }
            try {
                std::regex tg_rgx_ip ("^([0-9.]+)/([0-9.]+)/([0-9]+)/([0-9]+)$");
                std::regex tg_rgx_host ("^([a-z0-9]+)/([0-9.]+)/([0-9]+)/([0-9]+)$");
                std::string ia = argv[i+1];
                std::smatch m_rgx_ip;
                std::smatch m_rgx_host;
                if (std::regex_match(ia, m_rgx_ip, tg_rgx_ip)) {
                    receivers[cntr].listener.sin_family = AF_INET;
                    receivers[cntr].listener.sin_port = htons(stoi(m_rgx_ip[3]));
                    receivers[cntr].listener.sin_addr.s_addr = INADDR_ANY;
                    receivers[cntr].group.imr_multiaddr.s_addr = inet_addr(m_rgx_ip.str(2).c_str());
                    receivers[cntr].group.imr_interface.s_addr = inet_addr(m_rgx_ip.str(1).c_str());
                    receivers[cntr].duration = std::chrono::seconds(stoi(m_rgx_ip[4]));
                    cntr++;
                } else if (std::regex_match(ia, m_rgx_host, tg_rgx_host)) {
                    receivers[cntr].listener.sin_family = AF_INET;
                    receivers[cntr].listener.sin_port = htons(stoi(m_rgx_host[3]));
                    receivers[cntr].listener.sin_addr.s_addr = INADDR_ANY;
                    receivers[cntr].group.imr_multiaddr.s_addr = inet_addr(m_rgx_host.str(2).c_str());
                    receivers[cntr].duration = std::chrono::seconds(stoi(m_rgx_host[4]));
                    struct ifaddrs *ifaddr, *ifa;
                    int addr_family, n;
                    if (getifaddrs(&ifaddr) == -1) {
                        logit(ERROR, "failed to call getifaddrs() function");
                        exit(1);
                    }
                    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
                        if (ifa->ifa_addr == NULL)
                            continue;
                        addr_family = ifa->ifa_addr->sa_family;
                        /* reserved for IPv6
                        if (addr_family == AF_INET || addr_family == AF_INET6) {
                        */
                        if (addr_family == AF_INET) {
                            logit(ERROR, ifa->ifa_name);
                            if (ifa->ifa_name == m_rgx_host.str(1)) {
                                receivers[cntr].group.imr_interface.s_addr = ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr;
                                break;
                            }
                        }
                    }
                    freeifaddrs(ifaddr);
                    cntr++;
                } else {
                    logit(ERROR, "failed to provide a valid multicast listener traffic pattern via " + \
                          std::string(argv[i]) + ": " + ia);
                    exit(1);
                }
            } catch (std::regex_error& e) {
                regex_error_handler(e);
                exit(1);
            }
            i++;
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) {
            if (i+1 == argc) {
                logit(ERROR, "failed to supply a value for " + std::string(argv[i]) + " option");
                exit(1);
            }
            thc = stoi(argv[i+1]);
            i++;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--priority") == 0) {
            if (i+1 == argc) {
                logit(ERROR, "failed to supply a value for " + std::string(argv[i]) + " option");
                exit(1);
            }
            thrp = stoi(argv[i+1]);
            i++;
        } else if (strcmp(argv[i], "--random-payload") == 0) {
            RANDOMIZE = true;
        } else if (strcmp(argv[i], "--packet-storm") == 0) {
            PACKET_STORM = true;
        } else if (strcmp(argv[i], "--igmp-v2-report") == 0) {
            IGMP_REPORT_ONLY = true;
            USE_IGMP_V3 = false;
        } else if (strcmp(argv[i], "--igmp-v3-report") == 0) {
            IGMP_REPORT_ONLY = true;
            USE_IGMP_V3 = true;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemonize") == 0) {
            DAEMONIZE = true;
        } else if (strcmp(argv[i], "--non-root") == 0) {
            NON_ROOT = true;
        } else if (strcmp(argv[i], "--stop") == 0) {
            REQUESTED_STOP = true;
        } else if (strcmp(argv[i], "--status") == 0) {
            REQUESTED_STATUS = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            logit(INFO, "logging is enabled");
            VERBOSE = 1;
        } else {
            logit(ERROR, "option " + std::string(argv[i]) + " is invalid");
            exit(1);
        }
    }

    int thrn = std::thread::hardware_concurrency();
    int tptrs = cntr + cnts;

    if (VERBOSE == 2) {
        VERBOSE = 0;
    }

    if (REQUESTED_STOP == true) {
        VERBOSE = 1;
        stop();
        exit(0);
    }

    if (REQUESTED_STATUS == true) {
        logit(ERROR, "--status is not yet implemented");
        exit(1);
    }

    if (tptrs == 0) {
        logit(ERROR, "failed to provide a multicast traffic pattern");
        exit(1);
    }

    if (cnts > 0) {
        for( int i = 0; i < cnts; i++ ) {
            logit(INFO, " * sender pattern #" + std::to_string(i));
            logit(INFO, "   - interface name:  " + std::string(senders[i].interface));
            logit(INFO, "   - multicast group: " + ipv4_from_s_addr(senders[i].group.sin_addr.s_addr) + \
                        ":" + std::to_string(ntohs(senders[i].group.sin_port)));
            if (senders[i].count != 0) {
                logit(INFO, "   - packet count:    " + format_t(senders[i].count) + " / size (min/max): " + \
                        std::to_string(senders[i].low) + "/" + std::to_string(senders[i].high) + " bytes");
                if (senders[i].duration.count() > 0) {
                   logit(INFO, "   - duration:        " + format_t(senders[i].duration.count()) + " seconds");
                } else if (PACKET_STORM == true) {
                   logit(INFO, "   - duration:        until completed");
                } else {
                   logit(INFO, "   - duration:        until completed or aborted");
                }
                // if count != 0, then `duration` is used to calculate an interval together with count itself.
                // thus, the interval below is invalid.
                if (PACKET_STORM == true) {
                    logit(INFO, "   - w/out intervals, immediate");
                } else {
                    logit(INFO, "   - interval:        " + format_t(senders[i].interval.count()) + " microseconds");
                }
            } else {
                logit(INFO, "   - packet count:    unlimited, size (min/max): " + \
                        std::to_string(senders[i].low) + "/" + std::to_string(senders[i].high) + " bytes");
                // if count == 0, then `duration` becomes `interval`.
                if (PACKET_STORM == true) {
                    logit(INFO, "   - w/out intervals, immediate");
                } else {
                    logit(INFO, "   - interval:        " + format_t(senders[i].interval.count()) + " microseconds");
                }
            }
            if (senders[i].offset.count() > 0) {
                logit(INFO, "   - offset:          " + format_t(senders[i].offset.count()) + " seconds");
            } else {
                logit(INFO, "   - immediate start, no offset");
            }
            logit(INFO, "   - tag:             " + senders[i].tag);
        }
    }

    if (cntr > 0) {
        for( int i = 0; i < cntr; i++ ) {
            logit(INFO, " * receiver pattern #" + std::to_string(i));
            logit(INFO, "   - interface ip:    " + ipv4_from_s_addr(receivers[i].group.imr_interface.s_addr));
            logit(INFO, "   - multicast group: " + ipv4_from_s_addr(receivers[i].group.imr_multiaddr.s_addr) + \
                        ":" + std::to_string(ntohs(receivers[i].listener.sin_port)));
            if (receivers[i].duration.count() > 0) {
                logit(INFO, "   - duration:        " + std::to_string(receivers[i].duration.count()) + " seconds");
            } else {
                logit(INFO, "   - duration:        until aborted");
            }
        }
    }

    if (thrn < tptrs) {
        logit(WARN, "the number of system resources available, e.g. CPU, is less than the number of patterns.");
    }

    logit(INFO, "threads requested/supported: " + std::to_string(thc) + "/" + std::to_string(thrn));

    if (thrp != 0) {
        logit(INFO, "requested scheduling priority: " + std::to_string(thrp));
        int cthrp;
        errno = 0;
        cthrp = getpriority(PRIO_PROCESS, getpid());
        if (cthrp == -1 && errno) {
            logit(ERROR, "failed to get scheduling priority");
        } else {
            logit(INFO, "current scheduling priority: " + std::to_string(cthrp));
        }
        errno = 0;
        cthrp = setpriority(PRIO_PROCESS, getpid(), thrp);
        if (cthrp == -1 && errno) {
            logit(ERROR, "failed to set scheduling priority");
        }
        errno = 0;
        cthrp = getpriority(PRIO_PROCESS, getpid());
        if (cthrp == -1 && errno) {
            logit(ERROR, "failed to get scheduling priority");
        } else {
            logit(INFO, "current scheduling priority: " + std::to_string(cthrp));
        }
    } else {
        logit(INFO, "default scheduling priority: " + std::to_string(thrp));
    }

    signal(SIGQUIT, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGKILL, signal_handler);

    fill_pkt_payload();

    std::thread mgr_thr;
    if (DAEMONIZE == false) {
        mgr_thr = std::thread(mgr_thread, senders, cnts, receivers, cntr);
        mgr_thr.join();
    } else {
        if (pid_t pid = fork()) {
            if (pid > 0) {
                logit(INFO, "fork() succeeded");
                exit(0);
            } else {
                logit(ERROR, "fork() failed");
                exit(1);
            }
        }
        if (setsid() < 0) {
            logit(ERROR, "failed to the new leader of the new session");
        }
        if(chdir("/") != 0) {
            logit(ERROR, "failed to switch to / (root) directory");
        }

        umask(0);

        if (pid_t pid = fork()) {
            if (pid > 0) {
                logit(INFO, "detached from a controlling terminal");
                exit(0);
            } else {
                logit(ERROR, "failed to detach from a controlling terminal");
                exit(1);
            }
        }
        close(0);
        close(1);
        close(2);
        mgr_thr = std::thread(mgr_thread, senders, cnts, receivers, cntr);
        mgr_thr.join();
    }
    exit(0);
}

