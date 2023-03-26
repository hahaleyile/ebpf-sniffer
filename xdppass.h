#ifndef XDPPASS_H
#define XDPPASS_H

struct packet_info
{
    __u64 timestamp;
    __u32 len;
    __u8 data[];
};

#endif // XDPPASS_H
