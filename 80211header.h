#pragma pack(push,1)
struct Type_Subtype {
    u_int16_t	fc;
    u_int16_t 	duration;
};
struct Beacon_frame {
    u_int8_t da[6];
    u_int8_t sa[6];
    u_int8_t bssid[6];
    u_int16_t seq_ctrl;
};
struct Data {
    u_int8_t da[6];  //Destination
    u_int8_t bssid[6];
    u_int8_t sa[6];  //Source
    u_int16_t seq_ctrl;
};
struct ProbeRequest {
    u_int8_t da[6];
    u_int8_t sa[6];
    u_int8_t bssid[6];
    u_int16_t seq_ctrl;
};
struct QosData41 {
    u_int8_t bssid[6];
    u_int8_t sta[6];
    u_int8_t da[6];
};
struct QosData42 {
    u_int8_t sta[6];
    u_int8_t bssid[6];
    u_int8_t sa[6];
};
struct Nullfunction{
    u_int8_t bssid[6];
    u_int8_t sta[6];
    u_int8_t da[6];
};
struct taged_parameter{
    u_int8_t tag_number;
    u_int8_t tag_length;
    u_int8_t tag_value[];
};
#pragma pack(pop)
