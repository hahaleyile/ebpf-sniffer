#ifndef ETHERNET_H
#define ETHERNET_H

#include "protocol.h"

enum class EtherTypes { IPV4, IPV6, ARP, UNKNOWN };

class Ethernet : public Protocol
{
private:
  QString srcMac;
  QString dstMac;
  bool hasPadding = false;

public:
  static QMap<quint16, QString> strEtherTypes;

  Ethernet(const unsigned char *data, qsizetype size);
  void treePrint(QTreeWidget *parent) override;
  EtherTypes getType();
  inline QString getSrc() { return srcMac; }
  inline QString getDst() { return dstMac; }
  void addPadding(const char *data, qsizetype size);
};

#endif // ETHERNET_H
