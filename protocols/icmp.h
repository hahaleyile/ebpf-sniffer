#ifndef ICMP_H
#define ICMP_H

#include "protocol.h"

class Icmp : public Protocol
{
private:
  quint16 id, seq;

public:
  static QMap<quint8, QString> strIcmpTypes;

  Icmp(const unsigned char *data, qsizetype size);
  void treePrint(QTreeWidget *parent) override;
  QString infoPrint() override;
};

#endif // ICMP_H
