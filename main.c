#include <stdio.h>
#include <pcap.h>
#include <string.h>

void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("packet captured! captured length: %d. original length: %d\n", header->caplen, header->len);
}

int main(int argc, char **argv) {
    char* device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevsp;
    pcap_findalldevs(&alldevsp, errbuf);


    pcap_if_t* temp;
    for (temp = alldevsp; temp != NULL; temp = temp->next)
    {
        // 'temp' is the pointer to the current item
        printf("device: %s\n", temp->name);
        printf("description: %s\n", temp->description);
    }

     char it_name[256];
     printf("enter the interface name: ");
     if (fgets(it_name, sizeof(it_name), stdin) == NULL) {
         return 1;
     }

    it_name[strcspn(it_name, "\n")] = 0;

    pcap_t *handle = pcap_create(it_name, errbuf);
    if (handle == NULL) {
        printf("cannot open the file: %s\n", errbuf);
        return 1;
    }

    pcap_set_buffer_size(handle, 2097152);

    pcap_activate(handle);
    printf("handle activated");
    pcap_loop(handle, 1, callback, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevsp);



    return 0;
}