#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstring>
#include <QCoreApplication>

static void initOpenSSL() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

// ============================================================
// DTLSWorker — runs all networking in a background thread
// ============================================================

DTLSWorker::DTLSWorker(int localPort, const QString &peerIP, int peerPort, bool isServer)
    : m_localPort(localPort), m_peerIP(peerIP), m_peerPort(peerPort), m_isServer(isServer) {}

DTLSWorker::~DTLSWorker()
{
    running = false;
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    if (sockfd != -1) closesocket((SOCKET)sockfd);
}

void DTLSWorker::sendData(const QByteArray &data)
{
    if (ssl && running)
        SSL_write(ssl, data.data(), data.size());
}

void DTLSWorker::connectToPeer()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCKET) {
        emit errorOccurred("socket 失败");
        WSACleanup();
        return;
    }
    sockfd = (qintptr)fd;

    sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(m_localPort);
    localAddr.sin_addr.s_addr = INADDR_ANY;

    SOCKET fd2 = (SOCKET)sockfd;
    if (bind(fd2, (sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        emit errorOccurred("bind 失败");
        closesocket(fd2);
        sockfd = -1;
        return;
    }

    ctx = SSL_CTX_new(m_isServer ? DTLS_server_method() : DTLS_client_method());
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        emit errorOccurred("加载 cert.pem 失败");
        return;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        emit errorOccurred("加载 key.pem 失败");
        return;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        emit errorOccurred("私钥与证书不匹配");
        return;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sockfd);

    sockaddr_in peerAddr{};
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(m_peerPort);
    QByteArray ipBytes = m_peerIP.toUtf8();
    inet_pton(AF_INET, ipBytes.data(), &peerAddr.sin_addr);

    BIO *bio = BIO_new_dgram((int)sockfd, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &peerAddr);
    SSL_set_bio(ssl, bio, bio);

    if (m_isServer) {
        if (SSL_accept(ssl) <= 0) {
            emit errorOccurred("DTLS 握手失败");
            return;
        }
    } else {
        if (SSL_connect(ssl) <= 0) {
            emit errorOccurred("DTLS 握手失败");
            return;
        }
    }

    running = true;
    emit connected();

    // Receive loop — use select() with timeout so the event loop
    // can process queued sendData() invocations between iterations.
    char buf[1024];
    while (running) {
        QCoreApplication::processEvents();
        if (!running) break;

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET((SOCKET)sockfd, &readSet);
        timeval tv{0, 50000}; // 50 ms

        int sel = select(0, &readSet, nullptr, nullptr, &tv);
        if (sel > 0 && FD_ISSET((SOCKET)sockfd, &readSet)) {
            int len = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (len <= 0) break;
            buf[len] = 0;
            emit dataReceived(QString::fromUtf8(buf));
        } else if (sel < 0) {
            break; // select error
        }
    }
}

// ============================================================
// MainWindow
// ============================================================

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("DTLS 点对点 P2P 加密通信");
    setFixedSize(500, 450);

    auto *central = new QWidget(this);
    setCentralWidget(central);
    auto *ly = new QVBoxLayout(central);

    auto *ly1 = new QHBoxLayout;
    ly1->addWidget(new QLabel("本地端口:"));
    ed_localPort = new QLineEdit("9000");
    ly1->addWidget(ed_localPort);

    auto *ly2 = new QHBoxLayout;
    ly2->addWidget(new QLabel("对方IP:"));
    ed_peerIP = new QLineEdit("127.0.0.1");
    ly2->addWidget(ed_peerIP);

    auto *ly2b = new QHBoxLayout;
    ly2b->addWidget(new QLabel("对方端口:"));
    ed_peerPort = new QLineEdit("9001");
    ly2b->addWidget(ed_peerPort);
    ly2b->addWidget(new QLabel("角色:"));
    cmb_role = new QComboBox;
    cmb_role->addItem("客户端 (主动连接)");
    cmb_role->addItem("服务端 (等待连接)");
    ly2b->addWidget(cmb_role);

    auto *btnStart = new QPushButton("启动 DTLS 连接");
    connect(btnStart, &QPushButton::clicked, this, &MainWindow::startDTLS);

    txt_recv = new QTextEdit;
    txt_recv->setReadOnly(true);

    auto *ly3 = new QHBoxLayout;
    ed_send = new QLineEdit;
    auto *btnSend = new QPushButton("发送");
    ly3->addWidget(ed_send);
    ly3->addWidget(btnSend);
    connect(btnSend, &QPushButton::clicked, this, &MainWindow::sendData);

    ly->addLayout(ly1);
    ly->addLayout(ly2);
    ly->addLayout(ly2b);
    ly->addWidget(btnStart);
    ly->addWidget(new QLabel("接收消息:"));
    ly->addWidget(txt_recv);
    ly->addLayout(ly3);

    initOpenSSL();
}

MainWindow::~MainWindow()
{
    if (workerThread) {
        workerThread->quit();
        workerThread->wait(3000);
    }
}

void MainWindow::startDTLS()
{
    if (worker) {
        QMessageBox::information(this, "", "已运行");
        return;
    }

    int localPort = ed_localPort->text().toInt();
    QString ip = ed_peerIP->text();
    int peerPort = ed_peerPort->text().toInt();
    bool isServer = (cmb_role->currentIndex() == 1);

    worker = new DTLSWorker(localPort, ip, peerPort, isServer);
    workerThread = new QThread(this);

    worker->moveToThread(workerThread);

    connect(workerThread, &QThread::started, worker, &DTLSWorker::connectToPeer);
    connect(worker, &DTLSWorker::connected, this, [this]() {
        txt_recv->append("=== DTLS 连接成功！ ===");
    });
    connect(worker, &DTLSWorker::errorOccurred, this, [this](const QString &msg) {
        QMessageBox::warning(this, "", msg);
        workerThread->quit();
        workerThread->wait();
        worker = nullptr;
        workerThread = nullptr;
    });
    connect(worker, &DTLSWorker::dataReceived, this, [this](const QString &text) {
        txt_recv->append(text);
    });
    connect(workerThread, &QThread::finished, worker, &QObject::deleteLater);

    workerThread->start();
}

void MainWindow::sendData()
{
    if (!worker) return;
    QByteArray data = ed_send->text().toUtf8();
    QMetaObject::invokeMethod(worker, [this, data]() {
        worker->sendData(data);
    }, Qt::QueuedConnection);
    ed_send->clear();
}
