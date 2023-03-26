#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "qtreewidget.h"
#include <QByteArray>
#include <QString>

QString toIpv4(QByteArray&& bytes);
QString toIpv6(QByteArray&& bytes);

class Protocol
{
protected:
    QByteArray bytes;
    int len;
public:
    Protocol(const unsigned char *data, qsizetype size);
    ~Protocol();
    virtual void treePrint(QTreeWidget*){};
    virtual QString infoPrint();
    inline int getLen(){return len;}
    inline auto getData(){
       return bytes.constData();
    }
};

#endif // PROTOCOL_H
