#ifndef WLAN_KEY_VALUE_H
#define WLAN_KEY_VALUE_H
#include <string>

using namespace std;
#pragma pack(push,1)
/********************Beacon info Key & value*******************/
struct beacon_info_value{
    int beacon_frame_count;
    int data;
    int ch;
    u_int8_t ESSID[33];
    int ESSID_Len;
};
struct bssid_station_key{
    u_int8_t bssid[6];
};
struct bssid_station_value{
    u_int8_t station[6];
    int frames;
};
#pragma pack(pop)
#endif // WLAN_KEY_VALUE_H

