#ifndef UNKNOWN_H
#define UNKNOWN_H

#include "protocol.h"

class Unknown : public Protocol
{
public:
    Unknown(const unsigned char *data, qsizetype size);
    void treePrint(QTreeWidget *parent) override;
};

#endif // UNKNOWN_H
