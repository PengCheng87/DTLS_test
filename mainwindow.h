#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QComboBox>
#include <QUdpSocket>
#include <QThread>
#include <QtGlobal>

extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}

class DTLSWorker : public QObject
{
    Q_OBJECT

public:
    DTLSWorker(int localPort, const QString &peerIP, int peerPort, bool isServer);
    ~DTLSWorker();

public slots:
    void connectToPeer();
    void sendData(const QByteArray &data);

signals:
    void connected();
    void errorOccurred(const QString &msg);
    void dataReceived(const QString &text);

private:
    int m_localPort;
    QString m_peerIP;
    int m_peerPort;
    bool m_isServer;
    SSL *ssl = nullptr;
    SSL_CTX *ctx = nullptr;
    qintptr sockfd = -1;
    bool running = false;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void startDTLS();
    void sendData();

private:
    QLineEdit *ed_localPort;
    QLineEdit *ed_peerIP;
    QLineEdit *ed_peerPort;
    QComboBox *cmb_role;
    QTextEdit *txt_recv;
    QLineEdit *ed_send;

    DTLSWorker *worker = nullptr;
    QThread *workerThread = nullptr;
};

#endif // MAINWINDOW_H