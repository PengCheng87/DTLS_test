// ============================================================
// 头文件包含
// ============================================================
#include "mainwindow.h"

// Qt 界面相关头文件
#include <QVBoxLayout>     // 垂直布局（从上到下排列控件）
#include <QHBoxLayout>     // 水平布局（从左到右排列控件）
#include <QLabel>          // 文字标签
#include <QMessageBox>     // 消息提示框（弹出警告/信息）
#include <QHeaderView>     // 表格的列头设置
#include <QFile>           // 文件读写（读取 cert.pem / key.pem）
#include <QNetworkDatagram> // UDP 数据报封装（包含发送者地址）
#include <QHostAddress>    // IP 地址的封装类
#include <QHostInfo>       // 本机主机名解析（替代 gethostname + getaddrinfo）

// ============================================================
// 注意：本文件不再包含 OpenSSL C API 和 Winsock 头文件！
//
// 旧版使用了：
//   #include <winsock2.h>     ← socket(), bind(), select()
//   #include <ws2tcpip.h>     ← inet_pton(), getaddrinfo(), gethostname()
//   extern "C" { #include <openssl/ssl.h> }  ← SSL_* API
//
// 现在全部由 Qt 封装：
//   QUdpSocket   → 替代 SOCKET + bind() + select()
//   QDtls        → 替代 SSL_CTX_new + SSL_new + BIO_new_dgram
//                  + SSL_accept/connect/read/write
//   QSslConfiguration  → 替代 SSL_CTX_use_certificate_file
//                         / SSL_CTX_use_PrivateKey_file
//   QHostInfo     → 替代 gethostname() + getaddrinfo()
// ============================================================

// ============================================================
// DTLSWorker 类的实现
// ============================================================

// ------------------------------------------------------------
// 构造函数
// 参数：
//   localPort - 本机绑定到哪个端口（如 9000）
//   peerIP    - 对方 IP 地址（字符串，如 "192.168.1.101"）
//   peerPort  - 对方的端口（如 9000）
// ------------------------------------------------------------
DTLSWorker::DTLSWorker(int localPort, const QString &peerIP, int peerPort)
    : m_localPort(localPort), m_peerIP(peerIP), m_peerPort(peerPort) {}

// ------------------------------------------------------------
// 析构函数
// 清理 QDtls 和 QUdpSocket 对象。
// 注意：这两个对象如果设置了 this 为 parent，在 DTLSWorker
// 销毁时会自动被 Qt 释放。但为了安全，仍显式 shutdown。
// ------------------------------------------------------------
DTLSWorker::~DTLSWorker()
{
    // 如果 DTLS 连接已加密，发送关闭通知给对方
    if (m_dtls && m_dtls->isConnectionEncrypted())
        m_dtls->shutdown(m_socket);

    // 显式释放对象（即使有 parent 关系，手动 delete 也安全）
    delete m_dtls;
    delete m_socket;
}

// ------------------------------------------------------------
// sendData() — 发送数据给对方
//
// 使用 QDtls::writeDatagramEncrypted() 替代旧版的 SSL_write()。
// Qt 内部会自动完成 DTLS 加密和 UDP 发送。
// ------------------------------------------------------------
void DTLSWorker::sendData(const QByteArray &data)
{
    if (m_dtls && m_dtls->isConnectionEncrypted())
        m_dtls->writeDatagramEncrypted(m_socket, data);
}

// ------------------------------------------------------------
// connectToPeer() — 核心函数：建立 DTLS 连接（非阻塞版本）
//
// 与旧版不同，这个函数不再有 while 循环！
// 所有后续操作（握手、接收）都通过 Qt 信号驱动：
//   - readyRead 信号 → onReadyRead() 处理收到的数据
//   - handshakeTimeout 信号 → onHandshakeTimeout() 处理超时
//
// 函数流程：
// 1. 自动协商角色（谁做服务端/客户端）
// 2. 创建 QUdpSocket 并绑定到本地端口
// 3. 创建 QDtls 对象并设置证书和私钥
// 4. 连接信号槽
// 5. 如果是客户端，主动发起握手
// ------------------------------------------------------------
void DTLSWorker::connectToPeer()
{
    // ============================================================
    // 第1步：自动协商 DTLS 角色
    //
    // 规则：比较大的一方当服务端，小的一方当客户端。
    // 原理见 mainwindow.h 中的详细解释。
    // ============================================================

    QHostAddress peerAddrIP(m_peerIP);
    QHostAddress localIP;

    // 判断对方是不是 127.0.0.1（本机回环地址）
    if (peerAddrIP.isLoopback()) {
        localIP = QHostAddress("127.0.0.1");
    } else {
        // 真实联网：用 Qt 的 QHostInfo 获取本机 IPv4 地址
        // QHostInfo::fromName(localHostName) 替代了 gethostname + getaddrinfo
        QString localHostName = QHostInfo::localHostName();
        QHostInfo info = QHostInfo::fromName(localHostName);
        // 只取第一个 IPv4 地址，避免取到 IPv6 导致比较失败
        for (const QHostAddress &addr : info.addresses()) {
            if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
                localIP = addr;
                break;
            }
        }
    }

    // 比较 IP 和端口，决定角色
    if (peerAddrIP.toIPv4Address() != localIP.toIPv4Address())
        m_isServer = (peerAddrIP.toIPv4Address() > localIP.toIPv4Address());
    else
        m_isServer = (m_peerPort > m_localPort);

    // ============================================================
    // 第2步：创建 QUdpSocket 并绑定到本地端口
    //
    // QUdpSocket 是 Qt 对 UDP 套接字的封装，替代了旧版中
    // 的 socket() + bind() + select() 三件套。
    //
    // 关键区别：
    //   旧版：手动创建 SOCKET → bind → select() 轮询
    //   新版：QUdpSocket 创建 + bind → readyRead 信号自动触发
    // ============================================================
    m_socket = new QUdpSocket(this);

    // bind() 绑定到本机所有网卡的指定端口
    // QHostAddress::AnyIPv4 = 0.0.0.0（和旧的 INADDR_ANY 相同）
    if (!m_socket->bind(QHostAddress::AnyIPv4, m_localPort)) {
        emit errorOccurred("bind 失败: " + m_socket->errorString());
        return;
    }

    // ============================================================
    // 第3步：创建 QDtls 对象并加载证书和私钥
    //
    // QDtls 是 Qt 6.5+ 引入的 DTLS 封装类。
    // 它替代了旧版中多个 OpenSSL 对象的功能：
    //
    //   旧版：SSL_CTX_new(DTLS_*_method()) → SSL_new → BIO_new_dgram
    //   新版：new QDtls(mode) 一步到位
    //
    // QSslSocket::SslServerMode = 服务端模式（内部调用 SSL_accept）
    // QSslSocket::SslClientMode = 客户端模式（内部调用 SSL_connect）
    // ============================================================
    m_dtls = new QDtls(
        m_isServer ? QSslSocket::SslServerMode : QSslSocket::SslClientMode,
        this);  // 设置 this 为 parent，自动内存管理

    // 获取默认的 DTLS 配置
    QSslConfiguration config = QSslConfiguration::defaultDtlsConfiguration();

    // 禁用 DTLS Cookie 验证（简化握手流程）
    // Cookie 验证是 DTLS 防 DDoS 放大攻击的机制。
    // 在局域网 P2P 场景下可以安全地禁用。
    config.setDtlsCookieVerificationEnabled(false);

    // 关闭对端证书验证（因为使用自签名证书，没有 CA 签名）
    // 在局域网 P2P 场景中，双方使用预先交换的自签名证书，
    // 不需要通过 CA 进行证书链验证。
    config.setPeerVerifyMode(QSslSocket::VerifyNone);

    // ---- 加载证书（cert.pem）----
    // QSslCertificate 替代了 SSL_CTX_use_certificate_file()
    QFile certFile("cert.pem");
    if (!certFile.open(QIODevice::ReadOnly)) {
        emit errorOccurred("无法打开 cert.pem");
        return;
    }
    QSslCertificate cert(&certFile, QSsl::Pem);
    certFile.close();
    config.setLocalCertificate(cert);

    // ---- 加载私钥（key.pem）----
    // QSslKey 替代了 SSL_CTX_use_PrivateKey_file()
    QFile keyFile("key.pem");
    if (!keyFile.open(QIODevice::ReadOnly)) {
        emit errorOccurred("无法打开 key.pem");
        return;
    }
    QSslKey key(&keyFile, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    keyFile.close();
    config.setPrivateKey(key);

    // 将配置应用到 QDtls 对象
    m_dtls->setDtlsConfiguration(config);

    // 设置对方地址（告诉 QDtls 要和谁通信）
    m_dtls->setPeer(QHostAddress(m_peerIP), m_peerPort);

    // ============================================================
    // 第4步：连接信号槽
    //
    // 信号驱动代替旧版的 select() 轮询：
    //
    //   旧版：select() 每 50ms 轮询一次，用 processEvents() 处理事件
    //   新版：readyRead 信号 → 有数据时自动调用 onReadyRead()
    //        handshakeTimeout 信号 → 超时时自动处理
    //
    // 这是改造的核心优势：不再需要手动管理 I/O 循环。
    // ============================================================

    // 当 UDP 套接字收到数据包时，自动调用 onReadyRead()
    connect(m_socket, &QUdpSocket::readyRead,
            this, &DTLSWorker::onReadyRead);

    // 当 DTLS 握手超时时，自动调用 onHandshakeTimeout()
    connect(m_dtls, &QDtls::handshakeTimeout,
            this, &DTLSWorker::onHandshakeTimeout);

    // ============================================================
    // 第5步：启动握手
    //
    // 服务端和客户端的启动方式不同：
    //
    //   服务端：等待对方发来 ClientHello，收到后通过 readyRead
    //          触发 onReadyRead()，再调用 doHandshake() 处理。
    //          所以此处不做任何操作，等信号触发即可。
    //
    //   客户端：主动调用 doHandshake() 发送 ClientHello。
    //          QDtls 会自动处理后续的握手消息交换。
    //
    // doHandshake() 是非阻塞的，立即返回。
    // 握手完成后会通过 Qt 信号机制逐步推进状态，
    // 最终 handshakeState() 变为 HandshakeComplete。
    // ============================================================
    if (!m_isServer) {
        // 客户端模式：主动发起 DTLS 握手
        if (!m_dtls->doHandshake(m_socket)) {
            emit errorOccurred("客户端 DTLS 握手启动失败: "
                + m_dtls->dtlsErrorString());
            return;
        }
    }
    // 服务端模式：什么都不做，等待 readyRead 触发
}

// ------------------------------------------------------------
// onReadyRead() — 处理收到的 UDP 数据包
//
// 当 QUdpSocket 收到 UDP 数据包时，这个函数会被自动调用。
// 它的工作根据 DTLS 握手状态分为两种情况：
//
// 情况1：握手尚未完成
//   → 把收到的数据传给 doHandshake() 继续握手过程
//   → 如果握手刚完成，发射 connected() 信号
//
// 情况2：握手已完成（连接已加密）
//   → 用 decryptDatagram() 解密收到的数据
//   → 发射 dataReceived() 信号通知主界面显示
// ------------------------------------------------------------
void DTLSWorker::onReadyRead()
{
    // 循环读取所有待处理的数据报（一个 readyRead 可能触发多个包）
    while (m_socket->hasPendingDatagrams()) {
        // receiveDatagram() 返回 QNetworkDatagram，包含数据和发送者信息
        QNetworkDatagram dgram = m_socket->receiveDatagram();
        QByteArray data = dgram.data();

        // ---- 检查握手状态 ----
        if (m_dtls->handshakeState() != QDtls::HandshakeComplete) {
            // 【握手阶段】把这个数据报传给 QDtls 继续握手
            // 对服务端：第一个数据报就是 ClientHello
            // 对客户端：这是服务端的回复（ServerHello 等）
            if (!m_dtls->doHandshake(m_socket, data)) {
                emit errorOccurred("DTLS 握手失败: "
                    + m_dtls->dtlsErrorString());
                return;
            }

            // 检查握手是否刚完成
            if (m_dtls->handshakeState() == QDtls::HandshakeComplete) {
                emit connected();  // 通知主界面：连接成功！
            }
        } else {
            // 【加密通信阶段】解密收到的数据
            QByteArray plain = m_dtls->decryptDatagram(m_socket, data);
            if (!plain.isEmpty()) {
                // decryptDatagram 还可能返回 QDtls 内部的控制消息
                // （如重新协商），但通常是空字符串。
                // 只显示非空的内容。
                emit dataReceived(QString::fromUtf8(plain));
            }
        }
    }
}

// ------------------------------------------------------------
// onHandshakeTimeout() — 处理 DTLS 握手超时
//
// DTLS 基于 UDP（不可靠传输），握手消息可能丢失。
// 当 QDtls 检测到超时时，发射 handshakeTimeout 信号，
// 我们需要调用 handleTimeout() 重传必要的握手消息。
// ------------------------------------------------------------
void DTLSWorker::onHandshakeTimeout()
{
    if (m_dtls)
        m_dtls->handleTimeout(m_socket);
}

// ============================================================
// MainWindow 类的实现
// ============================================================

// ------------------------------------------------------------
// 构造函数：创建界面布局和控件
//
// 整体布局结构（从上到下）：
//
// ┌────────────────────────────────────────────┐
// │  本机基端口: [9000]                         │
// ├────────────────────────────────────────────┤
// │  对方列表:                                  │
// │  ┌──────────┬──────┬──────────┐            │
// │  │ IP       │ 端口  │ 状态     │            │
// │  ├──────────┼──────┼──────────┤            │
// │  │ 101      │ 9000 │ 已连接   │            │
// │  └──────────┴──────┴──────────┘            │
// │  IP:[____] 端口:[__] [添加] [删除选中]     │
// │         [启动所有连接]                      │
// ├────────────────────────────────────────────┤
// │  接收消息:                                  │
// │  ┌────────────────────────────────────┐    │
// │  │ [192.168.1.101:9000] Hello!        │    │
// │  └────────────────────────────────────┘    │
// │  [__________________] [发送]               │
// └────────────────────────────────────────────┘
//
// 注意：旧版构造函数中调用了 initOpenSSL()，现在不需要了。
// Qt6Network 内部已经初始化了 OpenSSL，无需手动调用。
// ============================================================
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("DTLS P2P 全网状加密通信");
    setFixedSize(620, 540);

    auto *central = new QWidget(this);
    setCentralWidget(central);

    auto *ly = new QVBoxLayout(central);

    // ---- 第1行：本机基端口 ----
    auto *ly1 = new QHBoxLayout;
    ly1->addWidget(new QLabel("本机基端口:"));
    ed_basePort = new QLineEdit("9000");
    ed_basePort->setFixedWidth(80);
    ly1->addWidget(ed_basePort);
    ly1->addStretch();
    ly->addLayout(ly1);

    // ---- 第2行：对方列表表格 ----
    ly->addWidget(new QLabel("对方列表:"));
    table_peers = new QTableWidget(0, 3);
    table_peers->setHorizontalHeaderLabels({"IP", "端口", "状态"});
    table_peers->horizontalHeader()->setStretchLastSection(true);
    table_peers->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_peers->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ly->addWidget(table_peers);

    // ---- 第3行：添加/删除对方的控件 ----
    auto *lyAdd = new QHBoxLayout;
    lyAdd->addWidget(new QLabel("IP:"));
    ed_addIP = new QLineEdit("192.168.1.101");
    lyAdd->addWidget(ed_addIP);
    lyAdd->addWidget(new QLabel("端口:"));
    ed_addPort = new QLineEdit("9001");
    ed_addPort->setFixedWidth(60);
    lyAdd->addWidget(ed_addPort);

    auto *btnAdd = new QPushButton("添加");
    connect(btnAdd, &QPushButton::clicked, this, &MainWindow::addPeer);
    lyAdd->addWidget(btnAdd);

    auto *btnRemove = new QPushButton("删除选中");
    connect(btnRemove, &QPushButton::clicked, this, &MainWindow::removePeer);
    lyAdd->addWidget(btnRemove);
    lyAdd->addStretch();
    ly->addLayout(lyAdd);

    // ---- 第4行：启动按钮 ----
    auto *btnStart = new QPushButton("启动所有连接");
    connect(btnStart, &QPushButton::clicked, this, &MainWindow::startAll);
    ly->addWidget(btnStart);

    // ---- 第5行：接收消息区域 ----
    ly->addWidget(new QLabel("接收消息:"));
    txt_recv = new QTextEdit;
    txt_recv->setReadOnly(true);
    ly->addWidget(txt_recv);

    // ---- 第6行：发送消息 ----
    auto *lySend = new QHBoxLayout;
    ed_send = new QLineEdit;
    auto *btnSend = new QPushButton("发送");
    connect(btnSend, &QPushButton::clicked, this, &MainWindow::sendData);
    connect(ed_send, &QLineEdit::returnPressed, this, &MainWindow::sendData);
    lySend->addWidget(ed_send);
    lySend->addWidget(btnSend);
    ly->addLayout(lySend);

    // 注意：不再需要调用 initOpenSSL()
    // Qt6Network 已经封装了 OpenSSL 的初始化
}

// ------------------------------------------------------------
// 析构函数：程序退出时清理所有连接
//
// 旧版需要逐个 quit() 和 wait() 线程，现在简单多了。
// 每个 worker 的 QDtls 和 QUdpSocket 都设了 this 为 parent，
// delete worker 时会自动清理所有子对象。
// ============================================================
MainWindow::~MainWindow()
{
    // 逐个清理每个对方的连接
    for (auto &entry : m_peers) {
        delete entry.worker;  // 自动清理内部的 m_dtls 和 m_socket
    }
}

// ------------------------------------------------------------
// addPeer() — 添加对方到列表
// ------------------------------------------------------------
void MainWindow::addPeer()
{
    QString ip = ed_addIP->text().trimmed();
    int port = ed_addPort->text().toInt();
    if (ip.isEmpty() || port <= 0) return;

    for (const auto &p : m_peers)
        if (p.ip == ip && p.port == port) return;

    PeerEntry e;
    e.ip = ip;
    e.port = port;
    m_peers.append(e);
    updateTable();
}

// ------------------------------------------------------------
// removePeer() — 删除选中的对方
//
// 旧版需要 thread->quit() + thread->wait(3000)，现在只需 delete。
// ============================================================
void MainWindow::removePeer()
{
    int row = table_peers->currentRow();
    if (row < 0 || row >= m_peers.size()) return;

    auto &e = m_peers[row];
    delete e.worker;   // 删除 worker 会自动断开连接和清理资源
    m_peers.removeAt(row);
    updateTable();
}

// ------------------------------------------------------------
// startAll() — 启动所有未连接的 DTLS 连接
//
// 旧版需要为每个连接创建 QThread 并 moveToThread：
//   worker->moveToThread(thread);
//   connect(thread, &QThread::started, worker, &DTLSWorker::connectToPeer);
//   thread->start();
//
// 现在 worker 直接在住线程运行，不需要 QThread：
//   worker = new DTLSWorker(...);
//   worker->connectToPeer();  // 直接调用，非阻塞立即返回
//
// 后续的所有 I/O 由 Qt 事件循环通过信号槽驱动。
// ============================================================
void MainWindow::startAll()
{
    int basePort = ed_basePort->text().toInt();
    if (basePort <= 0) {
        QMessageBox::warning(this, "", "请输入有效的本机基端口");
        return;
    }

    for (int i = 0; i < m_peers.size(); ++i) {
        auto &e = m_peers[i];
        if (e.worker) continue;

        int localPort = basePort + i;

        // 创建 worker（注意：不再需要 QThread！）
        e.worker = new DTLSWorker(localPort, e.ip, e.port);

        int idx = i;

        // 连接成功
        connect(e.worker, &DTLSWorker::connected, this, [this, idx]() {
            txt_recv->append(QString("=== 与 %1:%2 连接成功！ ===")
                .arg(m_peers[idx].ip).arg(m_peers[idx].port));
            updateTable();
        });

        // 收到消息
        connect(e.worker, &DTLSWorker::dataReceived, this, [this, idx](const QString &text) {
            txt_recv->append(QString("[%1:%2] %3")
                .arg(m_peers[idx].ip).arg(m_peers[idx].port).arg(text));
        });

        // 发生错误
        connect(e.worker, &DTLSWorker::errorOccurred, this, [this, idx](const QString &msg) {
            QMessageBox::warning(this, "",
                QString("[%1:%2] %3").arg(m_peers[idx].ip).arg(m_peers[idx].port).arg(msg));
            delete m_peers[idx].worker;
            m_peers[idx].worker = nullptr;
            updateTable();
        });

        // 直接调用 connectToPeer()（非阻塞）
        e.worker->connectToPeer();
    }
}

// ------------------------------------------------------------
// sendData() — 发送消息给所有已连接的对端
//
// 旧版需要 QMetaObject::invokeMethod + Qt::QueuedConnection
// 因为 worker 在另一个线程中执行。
//
// 现在 worker 在主线程，直接调用即可！不需要跨线程通信。
// ============================================================
void MainWindow::sendData()
{
    QByteArray data = ed_send->text().toUtf8();
    if (data.isEmpty()) return;

    for (auto &e : m_peers) {
        if (e.worker) {
            // 直接调用，不再需要 QMetaObject::invokeMethod
            e.worker->sendData(data);
        }
    }
    ed_send->clear();
}

// ------------------------------------------------------------
// updateTable() — 刷新对方列表表格
// ------------------------------------------------------------
void MainWindow::updateTable()
{
    table_peers->setRowCount(m_peers.size());
    for (int i = 0; i < m_peers.size(); ++i) {
        table_peers->setItem(i, 0, new QTableWidgetItem(m_peers[i].ip));
        table_peers->setItem(i, 1, new QTableWidgetItem(QString::number(m_peers[i].port)));
        QString status = m_peers[i].worker ? "已连接" : "未连接";
        table_peers->setItem(i, 2, new QTableWidgetItem(status));
    }
}
