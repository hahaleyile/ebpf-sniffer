#ifndef ARP_H
#define ARP_H

#include "protocol.h"
#include <QHostAddress>

class Arp : public Protocol
{
private:
  QString srcMac;
  QString dstMac;
  QHostAddress srcIP;
  QHostAddress dstIP;
public:
  Arp(const unsigned char *data, qsizetype size);
  QString infoPrint() override;
  inline QString getSrc() { return srcIP.toString(); }
  inline QString getDst() { return dstIP.toString(); }
  void treePrint(QTreeWidget *parent) override;
};

#endif // ARP_H
