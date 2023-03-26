#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "package.h"
#include "protocols/arp.h"
#include "protocols/ethernet.h"
#include "protocols/icmp.h"
#include "protocols/ipv4.h"
#include "xdppass.h"
#include <net/if.h>
#include <qscrollbar.h>
#include <QTime>
#include <typeinfo>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
  w = this;

  ui->setupUi(this);

  ui->tableWidget->setColumnWidth(0,80);
  ui->tableWidget->setColumnWidth(3,80);
  ui->tableWidget->setColumnWidth(4,60);

  // Connect the scrollbars for vertical scrolling
  connect(ui->plainTextEdit->verticalScrollBar(), &QScrollBar::valueChanged,
          ui->plainTextEdit_2->verticalScrollBar(), &QScrollBar::setValue);
  connect(ui->plainTextEdit->verticalScrollBar(), &QScrollBar::valueChanged,
          ui->plainTextEdit_3->verticalScrollBar(), &QScrollBar::setValue);
  connect(ui->plainTextEdit_2->verticalScrollBar(), &QScrollBar::valueChanged,
          ui->plainTextEdit->verticalScrollBar(), &QScrollBar::setValue);
  connect(ui->plainTextEdit_2->verticalScrollBar(), &QScrollBar::valueChanged,
          ui->plainTextEdit_3->verticalScrollBar(), &QScrollBar::setValue);
  connect(ui->plainTextEdit_3->verticalScrollBar(), &QScrollBar::valueChanged,
          ui->plainTextEdit->verticalScrollBar(), &QScrollBar::setValue);
  connect(ui->plainTextEdit_3->verticalScrollBar(), &QScrollBar::valueChanged,
          ui->plainTextEdit_3->verticalScrollBar(), &QScrollBar::setValue);

  struct if_nameindex *if_ni, *i;
  if_ni = if_nameindex();
  if (if_ni == NULL) {
      QMessageBox::critical(this,tr("App"),tr("Cannot find any network devices!"));
  }
  for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++)
      ui->comboBox->addItem(i->if_name);
  if_freenameindex(if_ni);
}

MainWindow::~MainWindow() {
  delete ui;

  // Detach the XDP program and clean up
    if(pre_if_index)
      bpf_set_link_xdp_fd(pre_if_index, -1, 0);
    if(ringBufferPtr)
    {
        ring_buffer__free(ringBufferPtr);
        bpf_object__close(obj);
    }
}

int handle_event(void *ctx, void *data, size_t size) {
    struct packet_info *pkt_info = static_cast<struct packet_info *>(data);
//    qDebug() << "pkt info data: " << QByteArray((const char*)pkt_info,32).toHex();
//    qDebug() << "origin data: " << QByteArray((const char*)pkt_info->data,4).toHex();

    w->setPktInfo(pkt_info);

    return 0;
}

void MainWindow::setPktInfo(struct packet_info *pkt_info){
  int row = ui->tableWidget->rowCount();
  if(!startTime)
        startTime = pkt_info->timestamp;
  Package *newPkg = new Package(pkt_info);
  packages.append(newPkg);
  ui->tableWidget->insertRow(row);
  ui->tableWidget->setItem(
      row, 0,
      new QTableWidgetItem(
          QTime(0, 0)
              .addMSecs((pkt_info->timestamp - startTime) / 1000000)
              .toString("hh:mm:ss.zzz")));
  ui->tableWidget->setItem(row, 4, new QTableWidgetItem(QString::number(pkt_info->len)));
  ui->tableWidget->setItem(row,1,new QTableWidgetItem(newPkg->src));
  ui->tableWidget->setItem(row,2,new QTableWidgetItem(newPkg->dst));
  const std::type_info& protocolType=typeid(*(newPkg->lastProtocol));
  if(protocolType== typeid(Ethernet))
    ui->tableWidget->setItem(row,3,new QTableWidgetItem("ETHERNET"));
  else if(protocolType== typeid(Arp))
    ui->tableWidget->setItem(row,3,new QTableWidgetItem("ARP"));
  else if(protocolType== typeid(Ipv4))
    ui->tableWidget->setItem(row,3,new QTableWidgetItem("IPV4"));
  else if(protocolType== typeid(Icmp))
    ui->tableWidget->setItem(row, 3, new QTableWidgetItem("ICMP"));
  else
    ui->tableWidget->setItem(row,3,new QTableWidgetItem("UNKNOWN"));
  ui->tableWidget->setItem(row,5,new QTableWidgetItem(newPkg->lastProtocol->infoPrint()));
  beFilited(row);

  if(ui->scrollBottom->isChecked())
  {
      ui->tableWidget->scrollToBottom();
  }
}

void MainWindow::on_actionstart_triggered() {
    if(!if_index)
      return;
    if(ui->actionstart->isChecked())
    {
        // load bpf program
        int prog_fd;
        int err = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
        if (err) {
          qDebug( "Error loading XDP program: %s\n", strerror(-err));
          exit(1);
        }

        err = bpf_set_link_xdp_fd(if_index, prog_fd, 0);
        if (err) {
          qDebug("Error attaching XDP program: %s\n", strerror(-err));
          exit(1);
        }

        // Get the ring buffer map
        struct bpf_map *ringBuffer = bpf_object__find_map_by_name(obj, "ringBuffer");
        // Get the ring buffer file descriptor
        int ringBufferFd = bpf_map__fd(ringBuffer);
        // Set up a ring buffer and start polling for packets
        ringBufferPtr = ring_buffer__new(ringBufferFd, handle_event, NULL, NULL);
        if (!ringBufferPtr) {
          qDebug("Error creating ring buffer\n");
          exit(1);
        }

        timeID=startTimer(100);
    }
    else{
        killTimer(timeID);

        // Detach the XDP program and clean up
        if (pre_if_index)
          bpf_set_link_xdp_fd(pre_if_index, -1, 0);
        if (ringBufferPtr) {
          ring_buffer__free(ringBufferPtr);
          ringBufferPtr = nullptr;
          bpf_object__close(obj);
        }
    }
    pre_if_index = if_index;
}

void MainWindow::timerEvent(QTimerEvent *event)
{
    int err = ring_buffer__poll(ringBufferPtr, 0);
    if (err < 0) {
      qDebug("Error polling ring buffer: %d\n", err);
    }
}


void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    int lines = (packages[row]->getLen() + 7) / 8;
    QString lineString;
    lineString.reserve(lines * 5 - 1);
    for (int i = 1; i <= lines; ++i) {
        lineString.append(QString::number(i).rightJustified(4,'0'));
        if(i!=lines)
              lineString.append('\n');
    }

    auto &&hexString = packages[row]->hexDump();

    auto &&asciiString=packages[row]->asciiDump();

    ui->plainTextEdit_3->setPlainText(lineString);
    ui->plainTextEdit->setPlainText(hexString);
    ui->plainTextEdit_2->setPlainText(asciiString);

    ui->treeWidget->clear();
    packages[row]->treePrint(ui->treeWidget);
    ui->treeWidget->expandAll();
}


void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    if_index = index + 1;
    // Detach the XDP program and clean up
    if(pre_if_index)
      bpf_set_link_xdp_fd(pre_if_index, -1, 0);
    if(ringBufferPtr)
    {
        ring_buffer__free(ringBufferPtr);
        ringBufferPtr = nullptr;
        bpf_object__close(obj);
    }
}

void MainWindow::filiter() {
    int rows = ui->tableWidget->rowCount();
    for (int i = 0; i < rows; ++i) {
        auto src = ui->tableWidget->item(i, 1)->text();
        auto dst = ui->tableWidget->item(i, 2)->text();
        auto pro = ui->tableWidget->item(i, 3)->text();
        auto ip=ui->lineEdit->text();
        auto mac=ui->lineEdit_2->text();
        auto p = ui->comboBox_2->itemText(ui->comboBox_2->currentIndex());
        bool hide = false;
        if (!ip.isEmpty() && ip != src && ip != dst) {
              ui->tableWidget->hideRow(i);
              hide=true;
        }
        if (!mac.isEmpty() && mac != src && mac != dst) {
              ui->tableWidget->hideRow(i);
              hide=true;
        }
        if (!p.isEmpty() && pro != p) {
              ui->tableWidget->hideRow(i);
              hide=true;
        }
        if(!hide)
              ui->tableWidget->showRow(i);
    }
}

void MainWindow::beFilited(int row)
{
    auto src = ui->tableWidget->item(row, 1)->text();
    auto dst = ui->tableWidget->item(row, 2)->text();
    auto pro = ui->tableWidget->item(row, 3)->text();
    auto ip = ui->lineEdit->text();
    auto mac = ui->lineEdit_2->text();
    auto p = ui->comboBox_2->itemText(ui->comboBox_2->currentIndex());
    bool hide = false;
    if (!ip.isEmpty() && ip != src && ip != dst) {
        ui->tableWidget->hideRow(row);
        hide = true;
        }
        if (!mac.isEmpty() && mac != src && mac != dst) {
        ui->tableWidget->hideRow(row);
        hide = true;
        }
        if (!p.isEmpty() && pro != p) {
              ui->tableWidget->hideRow(row);
              hide=true;
        }
        if(!hide)
              ui->tableWidget->showRow(row);
}

void MainWindow::on_lineEdit_editingFinished()
{
    filiter();
}


void MainWindow::on_lineEdit_2_editingFinished()
{
    filiter();
}


void MainWindow::on_comboBox_2_currentIndexChanged(int index)
{
    filiter();
}

