#include <arpa/inet.h>//ip -> bin
#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <radiotap.h>
#include <ieee802_11.h>
#include <netinet/in.h>

using namespace std;

#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

struct pcap_pkthdr *pkt_header;
struct ieee80211_radiotap_header *irh;  //ieee802.11 radiotap
struct mgmt_header_t *mh;   //ieee802.11 becon frame
char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char **argv)
{
    char *dev;
    dev = argv[1];
    if(argc < 2)
    {
        printf("Input argument error!\n");
        if (dev == NULL)
        {
            printf("Your device is : %s\n",dev);
            exit(1);
        }
    }
    else
    printf("DEV : %s\n", dev);

    pcap_t *fp;
    if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
    }
    const u_char *pkt_data;
    int res;
    int i;
    u_char *mac;
    int pkt_length;

    while(1)
    {
        while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
        {
            if(res == 0)continue;
            pkt_length = pkt_header->len;
            irh = (struct ieee80211_radiotap_header*)pkt_data;
            printf("-------------------ieee802.11 packet-------------------\n");
            printf("Header revision : %02x\n",irh->it_version);
            printf("Header pad : %02x\n",irh->it_pad);
            printf("Header length : %d\n",irh->it_len);
            printf("Present flags : %02x\n",irh->it_present);

            pkt_data += irh->it_len;
            pkt_length -= irh->it_len;

            mh = (struct mgmt_header_t*)pkt_data;
            printf("Frame control : %02x\n",mh->fc);    //Frame Control Field
            printf("Duration : %02x\n",mh->duration);   //Duration
            printf("address 1 : ");
            mac = mh->da;
            for(i=0;i<6;i++)
                printf("%02x:",(*mac++));
            printf("\n");
            printf("address 2 : ");
            mac = mh->sa;
            for(i=0;i<6;i++)
                printf("%02x:",(*mac++));
            printf("\n");
            printf("address 3 : ");
            mac = mh->bssid;
            for(i=0;i<6;i++)
                printf("%02x:",(*mac++));
            printf("\n");
            printf("Sequence number : %02x\n",ntohs(mh->seq_ctrl));

        }
    }
    return 0;
}
