// ============================================================
// 头文件包含
// ============================================================
#include "mainwindow.h"

// Qt 界面相关头文件
#include <QVBoxLayout>    // 垂直布局（从上到下排列控件）
#include <QHBoxLayout>    // 水平布局（从左到右排列控件）
#include <QLabel>         // 文字标签
#include <QMessageBox>    // 消息提示框（弹出警告/信息）
#include <QHeaderView>    // 表格的列头设置
#include <QCoreApplication> // Qt 核心应用（processEvents 用）
#include <QHostAddress>   // IP 地址的封装类（支持 IPv4/IPv6）

// Windows 网络相关头文件（Winsock2 API）
#include <winsock2.h>     // socket(), bind(), closesocket() 等
#include <ws2tcpip.h>     // inet_pton(), getaddrinfo() 等
#include <windows.h>      // Windows 系统 API

#include <cstring>        // C 字符串函数（如 memset）

// ============================================================
// initOpenSSL()
// 初始化 OpenSSL 库，只需在程序启动时调用一次。
// 加载加密算法和错误描述字符串，为后续的 SSL 操作做准备。
// ============================================================
static void initOpenSSL() {
    // 加载 SSL 和加密算法的错误字符串
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    // 加载人类可读的错误信息（如 "certificate verify failed"）
    SSL_load_error_strings();
    // 注册所有可用的加密算法（如 AES、RSA、SHA256 等）
    OpenSSL_add_all_algorithms();
}

// ============================================================
// DTLSWorker 类的实现
// ============================================================

// ------------------------------------------------------------
// 构造函数
// 参数：
//   localPort - 本机绑定到哪个端口（如 9000）
//   peerIP    - 对方 IP 地址（字符串，如 "192.168.1.101"）
//   peerPort  - 对方的端口（如 9000）
// 说明：
//   初始化列表语法（: m_localPort(localPort)...）把参数保存到成员变量。
//   QThread 的睡眠函数 msleep() 是静态的，不需要加 #include <QThread>，
//   因为在头文件中已经包含了。
// ------------------------------------------------------------
DTLSWorker::DTLSWorker(int localPort, const QString &peerIP, int peerPort)
    : m_localPort(localPort), m_peerIP(peerIP), m_peerPort(peerPort) {}

// ------------------------------------------------------------
// 析构函数
// 当 DTLSWorker 对象被 delete 时自动调用，清理所有资源。
// ------------------------------------------------------------
DTLSWorker::~DTLSWorker()
{
    // 通知接收循环退出
    running = false;

    // 如果有 SSL 连接对象
    if (ssl) {
        SSL_shutdown(ssl);  // 发送"关闭通知"给对方（优雅关闭）
        SSL_free(ssl);      // 释放 SSL 对象占用的内存
    }
    // 释放 SSL 上下文
    if (ctx) SSL_CTX_free(ctx);
    // 关闭 UDP 套接字（Winsock 用 closesocket，Linux 用 close）
    if (sockfd != -1) closesocket((SOCKET)sockfd);
}

// ------------------------------------------------------------
// sendData() — 发送数据给对方
// 这个函数从主线程通过 QueuedConnection 调用，在工作线程中执行。
// 参数 data 是待发送的二进制数据（QByteArray）。
// ------------------------------------------------------------
void DTLSWorker::sendData(const QByteArray &data)
{
    // 检查 SSL 连接是否有效且处于运行状态
    if (ssl && running)
        // SSL_write 加密数据并通过 DTLS 发送出去
        // 参数：SSL对象, 数据指针, 数据长度
        // 加密和解密由 OpenSSL 自动处理，对调用者透明
        SSL_write(ssl, data.data(), data.size());
}

// ------------------------------------------------------------
// connectToPeer() — 核心函数：建立 DTLS 连接
//
// 这个函数的执行流程：
// 1. 创建 UDP 套接字并绑定到本地端口
// 2. 自动协商角色（谁做服务端/客户端）
// 3. 加载证书和私钥
// 4. 创建 SSL 对象并设置 BIO（数据通道）
// 5. 执行 DTLS 握手（SSL_accept 或 SSL_connect）
// 6. 进入接收循环，持续等待对方消息
//
// 工作流程的关系图：
//   [用户点击"启动"] → [QThread 启动] → [connectToPeer() 开始执行]
//                                                   ↓
//   [UDP socket → bind → 协商角色 → 加载证书 → DTLS 握手成功]
//                                                   ↓
//                              ←[接收循环]→ 收到消息 → emit dataReceived
//                              ←[接收循环]→ 用户发送 → SSL_write
// ------------------------------------------------------------
void DTLSWorker::connectToPeer()
{
    // ============================================================
    // 第1步：初始化 Winsock（Windows 的网络库）
    // WSAStartup 告诉 Windows 我们要使用哪个版本的 Winsock API。
    // MAKEWORD(2,2) 表示请求 Winsock 2.2 版本。
    // 注意：每个线程都需要调用 WSAStartup（线程安全）。
    // ============================================================
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    // ============================================================
    // 第2步：创建 UDP 套接字
    //
    // socket() 的三个参数：
    //   AF_INET   - IPv4 协议（不是 IPv6）
    //   SOCK_DGRAM - UDP 协议（数据报模式）
    //             - 如果这里是 SOCK_STREAM 就是 TCP
    //             - 使用 SOCK_DGRAM 是证明使用 DTLS 的关键证据
    //   0         - 让系统自动选择合适的协议（UDP）
    //
    // DTLS vs TLS 的第一个区别：
    //   DTLS 基于 UDP → 用 SOCK_DGRAM
    //   TLS  基于 TCP → 用 SOCK_STREAM
    // ============================================================
    SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCKET) {
        emit errorOccurred("socket 失败");
        WSACleanup();
        return;
    }
    // 保存套接字描述符（qintptr 是指针大小的整数，兼容 32/64 位）
    sockfd = (qintptr)fd;

    // ============================================================
    // 第3步：绑定到本地端口
    //
    // sockaddr_in 是 IPv4 地址结构体，包含：
    //   sin_family - 地址族（必须是 AF_INET）
    //   sin_port   - 端口号（htons 转为网络字节序）
    //              - htons = Host TO Network Short
    //              - 因为不同 CPU 的字节顺序不同（大端/小端）
    //              - 网络传输统一用大端序，所以需要转换
    //   sin_addr   - IP 地址（INADDR_ANY = 0.0.0.0 表示绑定所有网卡）
    //
    // bind() 把套接字和端口关联起来。之后系统收到发往这个端口
    // 的 UDP 数据包，就会交给这个套接字处理。
    // ============================================================
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

    // ============================================================
    // 第4步：自动协商 DTLS 角色
    //
    // DTLS 要求通信双方必须有一方是"服务端"(server)，
    // 另一方是"客户端"(client)。
    //   - 服务端：等待对方连接（SSL_accept）
    //   - 客户端：主动连接对方（SSL_connect）
    //
    // 为了让用户不需要手动选择角色，我们通过比较
    // (本机IP, 本机端口) 和 (对方IP, 对方端口) 来自动决定：
    //
    // 规则：比较大的一方当服务端，小的一方当客户端。
    // 原理：这样保证同一对连接中，两方计算结果总是相反的。
    //       比如 A(9000) 和 B(9001)：
    //         A 是 小(B的9001 > A的9000) → A 是客户端
    //         B 是 大(比较B自己的9001 > A的9000) → B 是服务端
    // ============================================================

    // 把字符串 IP 转为 QHostAddress 对象（方便比较）
    QHostAddress peerAddrIP(m_peerIP);
    QHostAddress localIP;

    // 判断对方是不是 127.0.0.1（本机回环地址）
    // 如果双方都在同一台电脑测试，gethostname 获取到的是
    // 局域网 IP（如 192.168.1.100），不是 127.0.0.1。
    // 此时直接用 127.0.0.1 作为本地 IP 参与比较。
    if (peerAddrIP.isLoopback()) {
        localIP = QHostAddress("127.0.0.1");
    } else {
        // 真实联网情况：获取本机在局域网中的实际 IP
        char localHost[256];
        gethostname(localHost, sizeof(localHost));  // 获取计算机名

        // getaddrinfo 将计算机名解析为 IP 地址
        struct addrinfo hints{}, *res;
        hints.ai_family = AF_INET;       // 只查 IPv4
        hints.ai_socktype = SOCK_DGRAM;  // UDP 套接字
        if (getaddrinfo(localHost, nullptr, &hints, &res) == 0) {
            // inet_ntoa 将二进制 IP 转为点分十进制字符串（如 "192.168.1.100"）
            localIP = QHostAddress(QString(inet_ntoa(((sockaddr_in *)res->ai_addr)->sin_addr)));
            freeaddrinfo(res);  // 释放内存
        }
    }

    // 比较 IP 和端口，决定角色
    bool isServer;
    if (peerAddrIP.toIPv4Address() != localIP.toIPv4Address())
        // IP 不同时，IP 大的当服务端
        isServer = (peerAddrIP.toIPv4Address() > localIP.toIPv4Address());
    else
        // IP 相同时（如都是 127.0.0.1），端口大的当服务端
        isServer = (m_peerPort > m_localPort);

    // ============================================================
    // 第5步：创建 SSL 上下文并加载证书
    //
    // SSL_CTX（SSL Context）是 SSL 的配置对象。
    // 它包含：
    //   - 使用哪个协议版本（DTLS 1.2）
    //   - 本地证书和私钥
    //   - 其他安全参数
    //
    // DTLS vs TLS 的第二个区别：
    //   DTLS_server_method() → 生成 DTLS 服务端
    //   TLS_server_method()  → 生成 TLS 服务端
    // ============================================================
    ctx = SSL_CTX_new(isServer ? DTLS_server_method() : DTLS_client_method());

    // 加载证书文件 cert.pem。
    // 证书 = 公钥 + 身份信息。作用是让对方验证你的身份。
    // 就像身份证：上面有你的照片（公钥）和名字（身份）。
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        emit errorOccurred("加载 cert.pem 失败");
        return;
    }

    // 加载私钥文件 key.pem。
    // 私钥 = 只有你自己知道的密钥，用来解密对方加密的数据。
    // 警告：私钥绝对不能泄露给任何人！
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        emit errorOccurred("加载 key.pem 失败");
        return;
    }

    // 检查证书和私钥是否匹配（由同一个密钥对生成）
    if (!SSL_CTX_check_private_key(ctx)) {
        emit errorOccurred("私钥与证书不匹配");
        return;
    }

    // ============================================================
    // 第6步：创建 SSL 对象并绑定到 UDP 套接字
    //
    // SSL_new(ctx)   - 从上下文创建 SSL 连接对象
    // SSL_set_fd()   - 把套接字关联到 SSL 对象（告诉 OpenSSL
    //                  用哪个套接字收发数据）
    //
    // 设置对方地址：把用户输入的 IP:端口填入 sockaddr_in 结构体。
    // inet_pton() 把 "192.168.1.101" 这样的字符串转为二进制的 IP 地址。
    // ============================================================
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sockfd);

    // 构造对方地址
    sockaddr_in peerAddr{};
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(m_peerPort);
    QByteArray ipBytes = m_peerIP.toUtf8();
    inet_pton(AF_INET, ipBytes.data(), &peerAddr.sin_addr);

    // ============================================================
    // 第7步：创建 DTLS 专用的 BIO
    //
    // BIO（Basic I/O）是 OpenSSL 的 I/O 抽象层。
    // 它封装了底层的网络操作（读/写），让 SSL 对象不需要
    // 直接操作套接字。
    //
    // DTLS vs TLS 的第三个区别：
    //   DTLS: BIO_new_dgram()  → 数据报模式 BIO（UDP）
    //   TLS:  BIO_new_socket() → 流模式 BIO（TCP）
    //
    // BIO_ctrl(BIO_CTRL_DGRAM_SET_PEER) 告诉 DTLS 对方的地址，
    // 之后 SSL_write 就知道把数据包发给谁了。
    // ============================================================
    BIO *bio = BIO_new_dgram((int)sockfd, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &peerAddr);
    SSL_set_bio(ssl, bio, bio);

    // ============================================================
    // 第8步：执行 DTLS 握手
    //
    // DTLS 握手过程（UDP 版本，比 TCP 复杂）：
    //
    // 客户端（Client）                   服务端（Server）
    //     │                                   │
    //     │──── ClientHello ──────────────→    │
    //     │                                   │
    //     │    ←──── HelloVerifyRequest ────  │  （← DTLS 独有的防攻击机制）
    //     │                                   │
    //     │──── ClientHello (with cookie) →   │
    //     │    ←──── ServerHello ──────────   │
    //     │    ←──── Certificate ──────────   │
    //     │    ←──── ServerHelloDone ──────   │
    //     │                                   │
    //     │──── Certificate ──────────────→   │
    //     │──── ClientKeyExchange ───────→    │
    //     │──── Finished ────────────────→    │
    //     │                                   │
    //     │    ←──── Finished ─────────────   │
    //     │                                   │
    //     │  ← 加密通信开始 →                  │
    //
    // SSL_accept() = 服务端等待并处理握手（阻塞直到完成）
    // SSL_connect() = 客户端发起握手（阻塞直到完成）
    // ============================================================
    if (isServer) {
        // 服务端：等待对方连接
        if (SSL_accept(ssl) <= 0) {
            emit errorOccurred("DTLS 握手失败");
            return;
        }
    } else {
        // 客户端：主动连接对方，加入重试机制
        // 原因：服务端可能还没准备好（用户几乎同时点击"启动"）
        // 重试5次，每次间隔500毫秒，总共2.5秒的超时
        int retries = 5;
        bool ok = false;
        for (int i = 0; i < retries; ++i) {
            if (SSL_connect(ssl) > 0) { ok = true; break; }
            QThread::msleep(500);  // 等500毫秒再试
        }
        if (!ok) {
            emit errorOccurred("DTLS 握手失败");
            return;
        }
    }

    // ============================================================
    // 第9步：进入接收循环
    //
    // DTLS 握手成功后，进入主循环等待对方发送消息。
    // 使用 select() 函数监听套接字，有新数据时用 SSL_read 读取。
    // select() 是 Linux/Windows 都支持的 I/O 复用函数。
    //
    // 为什么用 select() 而不是直接 SSL_read()？
    // - SSL_read() 如果没有数据会一直阻塞，线程无法做其他事
    // - select() 可以设置超时（50毫秒），没数据时返回0
    // - 利用这个超时，定期调用 processEvents() 处理 Qt 事件
    // - 这样主线程通过 invokeMethod 发来的 sendData 才能被执行
    // ============================================================

    // 标记为运行状态
    running = true;
    // 通知主界面"连接成功"
    emit connected();

    // 接收缓冲区（最多存1023个字符 + 结尾的 \0）
    char buf[1024];

    while (running) {
        // 处理 Qt 事件队列（让 sendData 等跨线程调用能被处理）
        QCoreApplication::processEvents();
        // 如果外部要求停止（用户关闭程序或删除连接），立即退出
        if (!running) break;

        // ============================================================
        // select() — 检查套接字是否有数据可读
        //
        // 参数说明：
        //   readSet   - 要监视的套接字集合
        //   FD_ZERO   - 清空集合
        //   FD_SET    - 把我们的套接字加入集合
        //   timeval   - 超时时间：0秒50000微秒 = 50毫秒
        //
        // 返回值：
        //   > 0  → 有数据可读（套接字在集合中）
        //   = 0  → 超时（50ms内没有数据）
        //   < 0  → 出错
        // ============================================================
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET((SOCKET)sockfd, &readSet);
        timeval tv{0, 50000};  // 50毫秒

        int sel = select(0, &readSet, nullptr, nullptr, &tv);
        if (sel > 0 && FD_ISSET((SOCKET)sockfd, &readSet)) {
            // 有数据！用 SSL_read 解密读取
            // SSL_read 会自动解密 DTLS 数据包
            int len = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (len <= 0) break;  // 连接断开或出错
            buf[len] = 0;         // 字符串结尾
            // 发射信号通知主界面显示收到的消息
            emit dataReceived(QString::fromUtf8(buf));
        } else if (sel < 0) {
            break;  // select 出错
        }
    }
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
// ------------------------------------------------------------
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // 设置窗口标题和固定大小
    setWindowTitle("DTLS P2P 全网状加密通信");
    setFixedSize(620, 540);

    // central widget：QMainWindow 需要一个中央控件
    auto *central = new QWidget(this);
    setCentralWidget(central);

    // 垂直布局：控件从上到下排列
    auto *ly = new QVBoxLayout(central);

    // ---- 第1行：本机基端口 ----
    // "基端口"的含义：第 i 个对方使用的本地端口 = basePort + i
    // 例如 basePort=9000，第1个对方用9000，第2个用9001...
    auto *ly1 = new QHBoxLayout;
    ly1->addWidget(new QLabel("本机基端口:"));
    ed_basePort = new QLineEdit("9000");
    ed_basePort->setFixedWidth(80);
    ly1->addWidget(ed_basePort);
    ly1->addStretch();  // 占位，让控件靠左
    ly->addLayout(ly1);

    // ---- 第2行：对方列表表格 ----
    ly->addWidget(new QLabel("对方列表:"));
    // 3列：IP、端口、状态
    table_peers = new QTableWidget(0, 3);
    table_peers->setHorizontalHeaderLabels({"IP", "端口", "状态"});
    table_peers->horizontalHeader()->setStretchLastSection(true);  // 最后一列自动拉伸
    table_peers->setSelectionBehavior(QAbstractItemView::SelectRows);  // 点击选中整行
    table_peers->setEditTriggers(QAbstractItemView::NoEditTriggers);   // 禁止编辑
    ly->addWidget(table_peers);

    // ---- 第3行：添加/删除对方的控件 ----
    auto *lyAdd = new QHBoxLayout;
    lyAdd->addWidget(new QLabel("IP:"));
    ed_addIP = new QLineEdit("192.168.1.101");  // 默认值方便测试
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
    txt_recv->setReadOnly(true);  // 只读（用来显示，不允许编辑）
    ly->addWidget(txt_recv);

    // ---- 第6行：发送消息 ----
    auto *lySend = new QHBoxLayout;
    ed_send = new QLineEdit;
    auto *btnSend = new QPushButton("发送");
    connect(btnSend, &QPushButton::clicked, this, &MainWindow::sendData);
    // 按回车键也能发送（更便捷）
    connect(ed_send, &QLineEdit::returnPressed, this, &MainWindow::sendData);
    lySend->addWidget(ed_send);
    lySend->addWidget(btnSend);
    ly->addLayout(lySend);

    // 最后：初始化 OpenSSL 库
    initOpenSSL();
}

// ------------------------------------------------------------
// 析构函数：程序退出时清理所有连接
// ------------------------------------------------------------
MainWindow::~MainWindow()
{
    // 逐个清理每个对方的连接
    for (auto &entry : m_peers) {
        if (entry.worker) {
            // 1. 通知工作线程退出接收循环
            entry.worker->stop();
            // 2. 告诉线程的事件循环退出（如果还在运行）
            entry.thread->quit();
            // 3. 等待线程最多3秒后结束
            entry.thread->wait(3000);
            // 4. 释放 worker 和 thread 对象
            delete entry.worker;
            delete entry.thread;
        }
    }
}

// ------------------------------------------------------------
// addPeer() — 添加对方到列表
// 读取 IP 和端口输入框的内容，加入到 m_peers 列表中。
// ------------------------------------------------------------
void MainWindow::addPeer()
{
    QString ip = ed_addIP->text().trimmed();  // 去掉首尾空格
    int port = ed_addPort->text().toInt();
    if (ip.isEmpty() || port <= 0) return;

    // 检查是否已经添加过相同的 IP:端口
    for (const auto &p : m_peers)
        if (p.ip == ip && p.port == port) return;

    // 创建新的 PeerEntry 并加入列表
    PeerEntry e;
    e.ip = ip;
    e.port = port;
    m_peers.append(e);
    updateTable();  // 刷新表格显示
}

// ------------------------------------------------------------
// removePeer() — 删除选中的对方
// ------------------------------------------------------------
void MainWindow::removePeer()
{
    int row = table_peers->currentRow();  // 获取当前选中的行号
    if (row < 0 || row >= m_peers.size()) return;

    auto &e = m_peers[row];
    // 如果已经建立了连接，先断开
    if (e.worker) {
        e.worker->stop();       // 通知退出接收循环
        e.thread->quit();       // 退出事件循环
        e.thread->wait(3000);   // 等待线程结束
        delete e.worker;        // 销毁 worker
        delete e.thread;        // 销毁 thread
    }
    // 从列表中移除
    m_peers.removeAt(row);
    updateTable();
}

// ------------------------------------------------------------
// startAll() — 启动所有未连接的 DTLS 连接
//
// 为列表中每个尚未建立连接的对方创建一个 DTLSWorker + QThread。
// 每个 worker 连接到不同的本地端口（basePort + 索引）。
//
// 关键概念：为什么需要多个本地端口？
// 每个 DTLS 连接需要独立的 UDP 套接字和端口。
// 就像打电话：和不同的人通话需要不同的电话线路（端口）。
// ------------------------------------------------------------
void MainWindow::startAll()
{
    int basePort = ed_basePort->text().toInt();
    if (basePort <= 0) {
        QMessageBox::warning(this, "", "请输入有效的本机基端口");
        return;
    }

    // 遍历每个对方
    for (int i = 0; i < m_peers.size(); ++i) {
        auto &e = m_peers[i];
        if (e.worker) continue;  // 已经连接了，跳过

        // 第 i 个对方使用本地端口 = basePort + i
        int localPort = basePort + i;

        // 创建 worker 和 thread
        e.worker = new DTLSWorker(localPort, e.ip, e.port);
        e.thread = new QThread(this);

        // 把 worker 移动到新线程
        // 之后所有在 worker 上执行的代码都在新线程中运行
        e.worker->moveToThread(e.thread);

        // 保存索引以便在 lambda 中引用
        int idx = i;

        // 当线程启动时，自动调用 worker 的 connectToPeer()
        connect(e.thread, &QThread::started, e.worker, &DTLSWorker::connectToPeer);

        // 连接成功：显示消息并刷新表格
        connect(e.worker, &DTLSWorker::connected, this, [this, idx]() {
            txt_recv->append(QString("=== 与 %1:%2 连接成功！ ===")
                .arg(m_peers[idx].ip).arg(m_peers[idx].port));
            updateTable();
        });

        // 收到消息：显示在接收区，加上对方 IP:端口 作为前缀
        connect(e.worker, &DTLSWorker::dataReceived, this, [this, idx](const QString &text) {
            txt_recv->append(QString("[%1:%2] %3")
                .arg(m_peers[idx].ip).arg(m_peers[idx].port).arg(text));
        });

        // 发生错误：弹出警告并清理连接
        connect(e.worker, &DTLSWorker::errorOccurred, this, [this, idx](const QString &msg) {
            QMessageBox::warning(this, "",
                QString("[%1:%2] %3").arg(m_peers[idx].ip).arg(m_peers[idx].port).arg(msg));
            auto &en = m_peers[idx];
            en.thread->quit();
            en.thread->wait();
            delete en.worker;
            delete en.thread;
            en.worker = nullptr;
            en.thread = nullptr;
            updateTable();
        });

        // 启动线程（这会导致 connectToPeer 被调用）
        e.thread->start();
    }
}

// ------------------------------------------------------------
// sendData() — 发送消息给所有已连接的对端
// ------------------------------------------------------------
void MainWindow::sendData()
{
    QByteArray data = ed_send->text().toUtf8();  // 转为 UTF-8 字节
    if (data.isEmpty()) return;

    // 遍历所有对方，把消息发给每个已连接的 worker
    for (auto &e : m_peers) {
        if (e.worker) {
            // 跨线程调用：使用 invokeMethod + QueuedConnection
            // QueuedConnection 把调用请求放入 worker 所在线程的事件队列
            // worker 的事件循环会在空闲时处理这个请求
            QMetaObject::invokeMethod(e.worker, [w = e.worker, data]() {
                w->sendData(data);
            }, Qt::QueuedConnection);
        }
    }
    // 清空输入框，准备输入下一条消息
    ed_send->clear();
}

// ------------------------------------------------------------
// updateTable() — 刷新对方列表表格
// ------------------------------------------------------------
void MainWindow::updateTable()
{
    // 设置表格行数
    table_peers->setRowCount(m_peers.size());
    for (int i = 0; i < m_peers.size(); ++i) {
        // 第0列：IP 地址
        table_peers->setItem(i, 0, new QTableWidgetItem(m_peers[i].ip));
        // 第1列：端口号
        table_peers->setItem(i, 1, new QTableWidgetItem(QString::number(m_peers[i].port)));
        // 第2列：连接状态（有 worker 代表已连接）
        QString status = m_peers[i].worker ? "已连接" : "未连接";
        table_peers->setItem(i, 2, new QTableWidgetItem(status));
    }
}
