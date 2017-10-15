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
struct QosData41 *qdata41;
struct QosData42 *qdata42;
struct taged_parameter *tag;
struct taged_parameter *p_tag;
struct bssid_station_value bsv;
struct beacon_info_value nbiv;
struct Nullfunction *nf;
struct ProbeRequest *pr;

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

    map<Mac,beacon_info_value>beacon_info;
    map<Mac,beacon_info_value>::iterator iter;

    map<Mac,bssid_station_value>station_info;
    map<Mac,bssid_station_value>::iterator iter2;

    Mac bssid;
    Mac station;

    while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
    {
        if(res == 0)continue;
        pkt_length = pkt_header->len;
        irh = (struct ieee80211_radiotap_header*)pkt_data;
        pkt_data += irh->it_len;        //jump to subtype pointer
        pkt_length -= irh->it_len;

        ts = (struct Type_Subtype*)pkt_data;

        switch(ts->fc){
        case 0x80:
        {
            //printf("Beacon Frame\n");
            pkt_data += 4;  //type_subtype length
            pkt_length -= 4;
            b_f = (struct Beacon_frame*)pkt_data;

            memcpy(bssid.mac_address, b_f->bssid, 6);

            if((iter = beacon_info.find(bssid)) != beacon_info.end()) {
                iter->second.beacon_frame_count += 1;
            }
            else
            {
                nbiv.beacon_frame_count = 1;
                nbiv.ch = 0;
                nbiv.data = 0;
                nbiv.ESSID_Len = 0;
                memset(nbiv.ESSID,0x00,32);
            }

            pkt_data +=32;  //jump to tag 20 + 12
            pkt_length -=32;

            while(pkt_length>0)
            {
                tag = (struct taged_parameter*)pkt_data;
                switch(tag->tag_number)
                case 0x00:
                    tag = (struct taged_parameter*)pkt_data;
                    if((iter = beacon_info.find(bssid)) == beacon_info.end())       //해당되는 키와 값이 있을 경우 ESSID를 갱신
                    {
                        memcpy(nbiv.ESSID,tag->tag_value,tag->tag_length);
                        nbiv.ESSID_Len = tag->tag_length;
                    }

                    pkt_data += (2+tag->tag_length);//total tag's length
                    pkt_length -= (2+tag->tag_length);

                case 0x01:
                    tag = (struct taged_parameter*)pkt_data;

                    pkt_data += 2+tag->tag_length;
                    pkt_length -= 2+tag->tag_length;

                case 0x03:
                    tag = (struct taged_parameter*)pkt_data;
                    memcpy(&nbiv.ch,tag->tag_value,tag->tag_length);
                    beacon_info.insert(pair<Mac, beacon_info_value>(bssid,nbiv));

                    pkt_data += 2+tag->tag_length;
                    pkt_length -= 2+tag->tag_length;

                    break;  //110 line tag switch case break
            }
            break;  //82 line subtype switch case break
        }
        case 0x4208:
        {
        //printf("Data\n");
            pkt_data += 4;  //type_subtype length
            pkt_length -= 4;
            data = (struct Data*)pkt_data;
            memcpy(bssid.mac_address, data->bssid, 6);
            if((iter = beacon_info.find(bssid)) != beacon_info.end()) {
                iter->second.data += 1;
            }
            else
            {
                nbiv.beacon_frame_count = 0;
                nbiv.ch = 0;
                nbiv.data = 1;
                nbiv.ESSID_Len = 0;
                memset(nbiv.ESSID,0x00,32);
                beacon_info.insert(pair<Mac, beacon_info_value>(bssid,nbiv));
            }
        break;
        }
        case 0x0040:
        {
            //ProbeRequest Packet
            pkt_data += 4;  //type_subtype length
            pkt_length -= 4;

            pr = (struct ProbeRequest*)pkt_data;

            memcpy(station.mac_address, pr->sa,6);
            memcpy(bsv.bssid, pr->bssid,6);

            if((iter2 = station_info.find(station)) != station_info.end()) {
                iter2->second.frames_count += 1;
            }
            else
            {
                bsv.frames_count = 1;
                memset(bsv.SSID,0x00,32);
                bsv.SSID_Len = 0;
                //station_info.insert(pair<Mac, bssid_station_value>(station,bsv));
            }
            pkt_data += 20;  //jump to tag 20
            pkt_length -= 20;

            p_tag = (struct taged_parameter*)pkt_data;

            if(p_tag->tag_number == 0 && p_tag->tag_length > 0)
            {
                memcpy(bsv.SSID,p_tag->tag_value,p_tag->tag_length);
                bsv.SSID_Len = p_tag->tag_length;
            }
            station_info.insert(pair<Mac, bssid_station_value>(station,bsv));
        break;
        }
        case 0x4188:
        {
            //printf("QosData\n");
            pkt_data += 4;  //type_subtype length
            pkt_length -= 4;
            qdata41 = (struct QosData41*)pkt_data;
            memcpy(bssid.mac_address, qdata41->bssid,6);
            memcpy(station.mac_address,qdata41->sta,6);
            memcpy(bsv.bssid,qdata41->bssid,6);

            if((iter = beacon_info.find(bssid)) != beacon_info.end()) {
                iter->second.data += 1;
            }
            else
            {
                nbiv.beacon_frame_count = 0;
                nbiv.ch = 0;
                nbiv.data = 1;
                nbiv.ESSID_Len = 0;
                memset(nbiv.ESSID,0x00,32);
                beacon_info.insert(pair<Mac, beacon_info_value>(bssid,nbiv));
            }
            if((iter2 = station_info.find(station)) != station_info.end()) {
                iter2->second.frames_count += 1;
            }
            else
            {
                bsv.frames_count = 1;
                memset(bsv.SSID,0x00,32);
                bsv.SSID_Len = 0;
                station_info.insert(pair<Mac, bssid_station_value>(station,bsv));
            }
            break;
        }
        case 0x4288:
        {
            //printf("QosData\n");
            pkt_data += 4;  //type_subtype length
            pkt_length -= 4;

            qdata42 = (struct QosData42*)pkt_data;

            memcpy(bssid.mac_address, qdata42->bssid,6);
            memcpy(station.mac_address,qdata42->sta,6);
            memcpy(bsv.bssid,qdata42->bssid,6);

            if((iter = beacon_info.find(bssid)) != beacon_info.end()) {
                iter->second.data += 1;
            }
            else
            {
                nbiv.beacon_frame_count = 0;
                nbiv.ch = 0;
                nbiv.data = 1;
                nbiv.ESSID_Len = 0;
                memset(nbiv.ESSID,0x00,32);
                beacon_info.insert(pair<Mac, beacon_info_value>(bssid,nbiv));
            }
            if((iter2 = station_info.find(station)) != station_info.end()) {
                iter2->second.frames_count += 1;
            }
            else
            {
                bsv.frames_count = 1;
                memset(bsv.SSID,0x00,32);
                bsv.SSID_Len = 0;
                station_info.insert(pair<Mac, bssid_station_value>(station,bsv));
            }
        break;
        }
        case 0x0148:
        case 0x0948:
        case 0x1148:
        case 0x1948:
        {
            //null function
            pkt_data += 4;  //type_subtype length
            pkt_length -= 4;

            nf = (struct Nullfunction*)pkt_data;

            memcpy(station.mac_address,nf->sta,6);
            memcpy(bsv.bssid,nf->bssid,6);
            if((iter2 = station_info.find(station)) != station_info.end()) {
                iter2->second.frames_count += 1;
            }
            else
            {
                bsv.frames_count = 1;
                memset(bsv.SSID,0x00,32);
                bsv.SSID_Len = 0;
                station_info.insert(pair<Mac, bssid_station_value>(station,bsv));
            }
        break;
        }
    }
        system("clear");
        cout<<"BSSID              Beacons\t#Data\tCH\tESSID"<<endl;
        for(iter = beacon_info.begin(); iter!=beacon_info.end(); advance(iter,1))
        {
            for(i=0;i<6;i++)
                printf("%02x ",iter->first.mac_address[i]); //beacon info key(bssid)
            printf("\t");
            cout<<iter->second.beacon_frame_count<<"\t";    //beacon's count
            cout<<iter->second.data<<"\t";                  //beacon data's count
            printf("%d\t",iter->second.ch);
            for(i=0;i<iter->second.ESSID_Len;i++)
                printf("%c",iter->second.ESSID[i]);
            cout<<endl;
        }
        cout<<"BSSID              Station              Frames\tProbe"<<endl;
        for(iter2 = station_info.begin(); iter2!=station_info.end(); advance(iter2,1))
        {
            for(i=0;i<6;i++)
                printf("%02x ",iter2->second.bssid[i]); //station bssid value(bssid)
            printf(" ");
            for(i=0;i<6;i++)
                printf("%02x ",iter2->first.mac_address[i]); //station key(station address)
            printf("\t");
            cout<<iter2->second.frames_count<<"\t";     //station frame's count
            for(i=0;i<iter2->second.SSID_Len;i++)
                printf("%c",iter2->second.SSID[i]);
            cout<<endl;
        }
    }
    return 0;
}
