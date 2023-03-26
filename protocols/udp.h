#ifndef UDP_H
#define UDP_H

#include "protocol.h"

class Udp : public Protocol
{
private:
    quint16 srcPort;
    quint16 dstPort;
    quint16 dataLen;

public:
    Udp(const unsigned char *data, qsizetype size);
    void treePrint(QTreeWidget *parent) override;
    QString infoPrint() override;
};

#endif // UDP_H
