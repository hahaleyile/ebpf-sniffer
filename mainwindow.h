#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "package.h"
#include <QMainWindow>
#include <bpf/libbpf.h>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

int handle_event(void *ctx, void *data, size_t size);

class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  MainWindow(QWidget *parent = nullptr);
  ~MainWindow();
  void setPktInfo(struct packet_info *);

private slots:
  void on_actionstart_triggered();

  void on_tableWidget_cellClicked(int row, int column);

protected:
  void timerEvent(QTimerEvent *event) override;

private slots:
  void on_comboBox_2_currentIndexChanged(int index);

private slots:
  void on_lineEdit_2_editingFinished();

private slots:
  void on_lineEdit_editingFinished();

private slots:
  void on_comboBox_currentIndexChanged(int index);

private:
  Ui::MainWindow *ui;
  struct bpf_object *obj;
  struct bpf_prog_load_attr prog_load_attr = {
      .file = "xdppass.o",
      .prog_type = BPF_PROG_TYPE_XDP,
  };
  int pre_if_index = 0;
  int if_index = 0;
  struct ring_buffer *ringBufferPtr=nullptr;
  int timeID;
  QList<Package*> packages;
  quint64 startTime = 0;
  void filiter();
  void beFilited(int row);
};

extern MainWindow *w;
#endif // MAINWINDOW_H
