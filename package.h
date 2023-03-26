#ifndef PACKAGE_H
#define PACKAGE_H

#include "protocols/protocol.h"
#include <QList>

class Package {
public:
  Package(struct packet_info *pkt_info);
  QString hexDump();
  QString asciiDump();
  inline int getLen() { return len; }
  void treePrint(QTreeWidget *parent);
  QString src;
  QString dst;
  Protocol* lastProtocol;

private:
  QList<Protocol *> protocols;
  int len;
};

#endif // PACKAGE_H
