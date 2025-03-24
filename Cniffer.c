// Imports
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <getopt.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Define error Exit
#define exit_with_error(msg) \
    do                       \
    {                        \
        perror(msg);         \
        exit(EXIT_FAILURE);  \
    } while (0)

// Filter options
typedef struct
{
    uint8_t transfer_protocol;
    char *source_ip;
    char *destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    char *source_interface;
    char *destination_interface;
    uint8_t source_mac[6];
    uint8_t destination_mac[6];
} packet_filter_type;

// Socket address holders
struct sockaddr_in source_address, dest_address;

// mac address solver for inteface
void get_mac_address(char *interface_name, packet_filter_type *packet, char *interface_type)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.idr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, if_name, IF_NAMESIZE - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close();
    if (strcmp(interface_type, "source") == 0)
    {
        strcpy(packet->source_mac, (uint8_t *)ifr.ifr_hwaddr.sa_data);
    }
    else
    {
        strcpy(packet->destination_mac, (uint8_t *)ifr.ifr_hwaddr.sa_data);
    }
}

// Compaire mac addresses (6 first bits)
uint8_t maccmp(uint8_t *mac1, uint8_t *mac2)
{
    for (uint8_t i = 0; i < 6; i++)
    {
        if (mac1[i] != mac2[i])
        {
            return 0;
        }
    }
    return 1;
}

// Main function
int main(int argc, char **argv)
{
    // Place holders
    int count;
    char log[225];
    FILE *logFile = NULL;
    packet_filter_type packet_filter = {0, NULL, NULL, 0, 0, NULL, NULL};
    struct sockaddr saddr;
    int sockfd, saddr_len, buff_len;
    uint8_t *buffer = (uint8_t *)malloc(65536);
    memset(buffer, 0, 65536);
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        exit_with_error("failed to create socket !")
    }

    // User input
    while (1)
    {
        static struct option long_options[] =
            {
                {"sip", required_argument, NULL, 's'},
                {"dip", required_argument, NULL, 'd'},
                {"sport", required_argument, NULL, 'p'},
                {"dport", required_argument, NULL, 'o'},
                {"sif", required_argument, NULL, 'i'},
                {"dif", required_argument, NULL, 'g'},
                {"logfile", required_argument, NULL, 'f'},
                {"tcp", no_argument, NULL, 't'},
                {"udp", no_argument, NULL, 'u'},
                {0, 0, 0, 0}};

        // Filtering output
        c = getopt_long(argc, argv, "tus:d:p:o:i:g:f", long_options, NULL);
        if (c == -1)
        {
            break;
        }
        switch (c)
        {
        case 't':
            packet_filter.transfer_protocol = IPPROTO_TCP;
            break;
        case 'u':
            packet_filter.transfer_protocol = IPPROTO_UDP;
            break;
        case 'p':
            packet_filter.source_port = atoi(optarg);
            break;
        case 'o':
            packet_filter.destination_port = atoi(optarg);
            break;
        case 's':
            packet_filter.source_ip = optarg;
            break;
        case 'd':
            packet_filter.destination_port = optarg;
            break;
        case 'i':
            packet_filter.source_interface = optarg;
            break;
        case 'g':
            packet_filter.destination_interface = optarg;
            break;
        case 'f':
            strcpy(log, optarg);
            break;
        default:
            abort();
        }
    }

    // Debugging user input
    printf("transfer_protocol : %d\n", packet_filter.transfer_protocol);
    printf("source_port : %d\n", packet_filter.source_port);
    printf("destination_port : %d\n", packet_filter.destination_port);
    printf("source_ip : %s\n", packet_filter.source_ip);
    printf("destination_port : %s\n", packet_filter.destination_ip);
    printf("source_interface : %s\n", packet_filter.source_interface);
    printf("destination_interface : %s\n", packet_filter.destination_interface);
    printf("log_file : %s\n", log);
    if (strlen(log) == 0)
    {
        strcpy(log, "Cniffer_log.txt");
    }
    logFile = fopen(log, "w");
    if (!logFile)
    {
        exit_with_error("failed to open log file !");
    }

    if (packet_filter.source_interface != NULL)
    {
        get_mac_address(packet_filter.source_interface, &packet_filter, "source");
    }
    if (packet_filter.destination_interface != NULL)
    {
        get_mac_address(packet_filter.destination_interface, &packet_filter, "destination");
    }

    // main LOOP
    while (1)
    {
    }
}