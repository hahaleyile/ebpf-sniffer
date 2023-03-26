#ifndef IPV4_H
#define IPV4_H

#include "protocol.h"
#include <QHostAddress>

enum class IpTypes { ICMP, TCP, UDP, UNKNOWN };

class Ipv4 : public Protocol
{
private:
  QHostAddress srcIP;
  QHostAddress dstIP;
public:
  static QMap<quint8, QString> strIpTypes;

  Ipv4(const unsigned char *data, qsizetype size);
  inline QString getSrc() { return srcIP.toString(); }
  inline QString getDst() { return dstIP.toString(); }
  IpTypes getType();
  void treePrint(QTreeWidget *parent) override;
};

#endif // IPV4_H
