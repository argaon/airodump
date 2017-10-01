#include <arpa/inet.h>//ip -> bin
#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <radiotap.h>
#include <netinet/in.h>
#include <map>
#include <string.h>
#include <unistd.h>
#include "80211header.h"
#include "wlan_key_value.h"
#include "mac.h"

using namespace std;

#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

struct pcap_pkthdr *pkt_header;
struct ieee80211_radiotap_header *irh;  //ieee802.11 radiotap
struct Type_Subtype *ts;
struct Beacon_frame *b_f;
struct Data *data;
struct taged_parameter *tag;
struct beacon_info_key *bik;
struct beacon_info_value *biv;
struct bssid_station_key *bsk;
struct bssid_station_value *bsv;

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
    int pkt_length;

    int p = 0;
    int q = 0;
    int n = 0;

    map<Mac,beacon_info_value>beacon_info;
    map<Mac,beacon_info_value>::iterator iter;


    map<bssid_station_key,bssid_station_value>station_info;
    map<bssid_station_key,bssid_station_value>::iterator iter2;

    Mac bssid;
    Mac station;


    while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
    {
        if(res == 0)continue;
        pkt_length = pkt_header->len;
        irh = (struct ieee80211_radiotap_header*)pkt_data;
        pkt_data += irh->it_len;
        pkt_length -= irh->it_len;

        ts = (struct Type_Subtype*)pkt_data;

        switch(ts->fc){
        case 0x80:
        {
            //printf("Beacon Frame\n");
            pkt_data += 4;  //type_subtype length
            pkt_length -= 4;
            b_f = (struct Beacon_frame*)pkt_data;
            struct beacon_info_value nbiv;
            memcpy(bssid.mac_address, b_f->bssid, 6);

            if((iter = beacon_info.find(bssid)) != beacon_info.end()) {
                iter->second.beacon_frame_count += 1;
            }
            else
            {
                nbiv.beacon_frame_count = 1;
                nbiv.ch = 0;
                nbiv.data = 0;
                memset(nbiv.ESSID,0x00,6);
                beacon_info.insert(pair<Mac, beacon_info_value>(bssid,nbiv));
            }
            pkt_data +=32;  //jump to tag 20 + 12
            pkt_length -=32;
            while(pkt_length>0)
            {
                tag = (struct taged_parameter*)pkt_data;
                switch(tag->tag_number)
                case 0x00:
                    tag = (struct taged_parameter*)pkt_data;
                    //printf("Tag Number : %02x\n",t0->tag_number);
                    printf("ESSID's length : %d\n",tag->tag_length);
                    for(i=0;i<tag->tag_length;i++)
                        printf("%c",tag->tag_value[i]);
                    printf("\n");
                    pkt_data += (2+tag->tag_length);//total tag's length
                    pkt_length -= (2+tag->tag_length);
                case 0x01:
                    tag = (struct taged_parameter*)pkt_data;
                    //printf("Tag Number : %02x\n",t1->tag_number);
                    pkt_data += 2+tag->tag_length;
                    pkt_length -= 2+tag->tag_length;
                case 0x03:
                    tag = (struct taged_parameter*)pkt_data;
                    //printf("Tag Number : %02x\n",t3->tag_number);
                    printf("Chanel : %02x\n",tag->tag_value[0]);
                    pkt_data += 2+tag->tag_length;
                    pkt_length -= 2+tag->tag_length;
                    break;
                default:
                    break;
            }
            break;
        }
        case 0x4208:
        //printf("Data\n");
            pkt_data += 4;  //type_subtype length
            pkt_length -= 4;
            data = (struct Data*)pkt_data;
            struct beacon_info_value nbiv;
            memcpy(bssid.mac_address, data->bssid, 6);
            if((iter = beacon_info.find(bssid)) != beacon_info.end()) {
                iter->second.data += 1;
            }
            else
            {
                nbiv.beacon_frame_count = 0;
                nbiv.ch = 0;
                nbiv.data = 1;
                memset(nbiv.ESSID,0x00,6);
                beacon_info.insert(pair<Mac, beacon_info_value>(bssid,nbiv));
            }
        break;
        case 0x40:
        //printf("Probe\n");
        p++;
        break;
        case 0x4188:
        case 0x4288:
        //printf("QosData\n");
        q++;
        break;
        case 0x1148:
        case 0x0148:
        case 0x0948:
        case 0x1948:
        n++;
        break;
    }
        //cout<<"BSSID : "<<(u_int8*)iter->first.mac_address<<endl;
        cout<<"BeaconFrame : "<<iter->second.beacon_frame_count<<endl;
        cout<<"#Data : "<<iter->second.data<<endl;
        //printf("#Data : %d\n",d);
        printf("Probe : %d\n",p);
        printf("QosData : %d\n",q);
        printf("Null : %d\n",n);        //count station to bssid data packet (null function + QOS data)
    }
    return 0;
}
