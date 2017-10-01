#pragma pack(push,1)
struct Type_Subtype {
    u_int16_t	fc;
    u_int16_t 	duration;
};
struct Beacon_frame {
    u_int8_t	da[6];
    u_int8_t	sa[6];
    u_int8_t	bssid[6];
    u_int16_t	seq_ctrl;
};
struct Data {
    u_int8_t    da[6];  //Destination
    u_int8_t    bssid[6];
    u_int8_t    sa[6];  //Source
    u_int16_t	seq_ctrl;
};
struct Probe {
    u_int8_t    da[6];  //Destination
    u_int8_t	sa[6];
    u_int8_t    bssid[6];
};
struct QosData {
    u_int8_t    bssid[6];
    u_int8_t    da[6];  //Destination
    u_int8_t	sa[6];
};
struct Block_ack {
    u_int8_t    ra[6];  //Receiver
    u_int8_t    ta[6];  //Transmitter
};
struct taged_parameter{
    u_int8_t tag_number;
    u_int8_t tag_length;
    u_int8_t tag_value[];
};

#pragma pack(pop)
