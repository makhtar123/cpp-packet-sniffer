#include <iostream>
#include <cstdio>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <cctype>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    printf("Time: %ld | Length: %d\n", header->ts.tv_sec, header->len);
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip*)(packet + 14);
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        switch (ip_header->ip_p) {
            case 6: // TCP
                {   // <--- ADD THIS OPENING BRACKET
                    printf("Protocol: TCP\n");
                    
                    // dynamically calculating ip header len
                    int ip_header_len = ip_header->ip_hl * 4;
                    
                    struct tcphdr *tcp_header;
                    tcp_header = (struct tcphdr*)(packet + 14 + ip_header_len);
                    
                    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
                    printf("Dest Port: %d\n", ntohs(tcp_header->th_dport)); 

                    int tcp_header_len = tcp_header->th_off * 4;
                    
                    // Calculate pointers and size
                    const u_char *payload = packet + 14 + ip_header_len + tcp_header_len;
                    int payload_size = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;

                    if (payload_size > 0) {
                        printf("Payload (%d bytes):\n", payload_size);
                        for (int i = 0; i < payload_size; i++) {
                            // Check if character is printable (needs #include <cctype>)
                            if (isprint(payload[i])) {
                                printf("%c", payload[i]);
                            } else {
                                printf(".");
                            }
                        }
                        printf("\n"); 
                    } else {
                        printf("No Payload.\n");
                    }
                }  
                break;
                
            case 17: // UDP
                {
                    printf("Protocol: UDP\n");
                    int ip_header_len = ip_header->ip_hl * 4;
                    struct udphdr *udp_header;
                    udp_header = (struct udphdr*)(packet + 14 +ip_header_len);
                    printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
                    printf("Dest Port: %d\n", ntohs(udp_header->uh_dport)); 
                }
                break;
                
            case 1: // ICMP
            {   
                printf("Protocol: ICMP\n");
                
                int ip_header_len = ip_header->ip_hl * 4;
                
                struct icmp *icmp_header;
                icmp_header = (struct icmp*)(packet + 14 + ip_header_len);

                printf("Type: %d\n", icmp_header->icmp_type);
                printf("Code: %d\n", icmp_header->icmp_code);
                
                // Optional: Make it human readable
                if (icmp_header->icmp_type == ICMP_ECHO) {
                    printf("(Ping Request)\n");
                } else if (icmp_header->icmp_type == ICMP_ECHOREPLY) {
                    printf("(Ping Reply)\n");
                }
            }
                break;
                
            default:
                printf("Protocol: Unknown (%d)\n", ip_header->ip_p);
                break;
        }
    }
    printf("----------------------------------------\n");
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle; // The session handle

    // 1. Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return(1);
    }

    // 2. Iterate through the list and print them
    device = alldevs;
    int count = 0;

    // Check if list is empty
    if (device == NULL) {
        printf("No devices found.\n");
        return(1);
    }

    printf("Available Devices:\n");
    while(device != NULL) {
        count++;
        printf("%d. %s", count, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
        
        device = device->next;
    }

    // 3. Ask user for input
    int choice;
    printf("Enter the number of the interface you want to sniff: ");
    scanf("%d", &choice);

    // 4. Validate Input (Prevent Crash)
    if(choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        pcap_freealldevs(alldevs); // Clean up before quitting
        return(1);
    }

    // 5. Navigate to the selected device
    device = alldevs; // Reset to start
    for(int i = 0; i < choice - 1; i++) {
        device = device->next;
    }

    printf("Selected device: %s\n", device->name);

    // 6. Open the device
    // 65536 = Capture full packet
    // 1 = Promiscuous mode (Capture everything)
    // 1000 = 1 second timeout
    handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return(2);
    }

    printf("Device opened successfully! Ready to capture.\n");
    std::cin.ignore(); 

    // 2. Get the string from the user
    std::string user_filter;
    printf("Enter BPF Filter (e.g., 'tcp port 80' or 'icmp'): ");
    std::getline(std::cin, user_filter);
    
    struct bpf_program fp;
    bpf_u_int32 net = 0;

    // 2. Compile the filter expression
    // pcap_compile(handle, &fp, expression, optimize, netmask)
    if (pcap_compile(handle, &fp, user_filter.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", 
                user_filter.c_str(), pcap_geterr(handle));
        return(2);
    }

    // 4. Apply
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter '%s': %s\n", 
                user_filter.c_str(), pcap_geterr(handle));
        return(2);
    }

    printf("Filter applied: %s\n", user_filter.c_str());

    // 7. Cleanup
    pcap_freealldevs(alldevs);

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    return(0);
}
