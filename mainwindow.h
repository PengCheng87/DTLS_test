#ifndef MAINWINDOW_H
#define MAINWINDOW_H

// ============================================================
// Qt 头文件说明
// ============================================================
#include <QMainWindow>    // 窗口框架（菜单栏、状态栏、工具栏等）
#include <QPushButton>    // 按钮控件
#include <QLineEdit>      // 单行文本输入框
#include <QTextEdit>      // 多行文本显示/编辑框
#include <QTableWidget>   // 表格控件（显示对方列表）
#include <QList>          // 动态数组（存储多个对方信息）
#include <QThread>        // 线程管理（网络操作在后台线程执行，不卡界面）
#include <QtGlobal>       // Qt 全局定义（如 qintptr 类型）

// ============================================================
// OpenSSL 头文件
// ============================================================
// OpenSSL 是 C 语言写的，在 C++ 中需要用 extern "C" 包裹
extern "C" {
#include <openssl/ssl.h>   // SSL/TLS/DTLS 核心 API
#include <openssl/err.h>   // 错误处理函数
}

// ============================================================
// DTLSWorker 类
// 负责与"一个"对方建立 DTLS 加密连接并进行网络通信。
// 每个 DTLSWorker 对象专门管理一条连接，运行在独立的线程中。
// 如果要连接多个对方，就需要创建多个 DTLSWorker（每个一个线程）。
// ============================================================
// 为什么需要 QThread 和 QObject？
// - 网络操作（如 SSL_accept、SSL_read）会阻塞等待，如果在主界面线程
//   中执行，界面就会"卡死"无法点击。
// - 把 DTLSWorker 放到 QThread 中运行，网络操作就不会影响界面响应。
// - DTLSWorker 继承 QObject 才能使用信号(signal)和槽(slot)机制，
//   跨线程安全地通知主界面"收到消息了"或"连接出错了"。
// ============================================================
class DTLSWorker : public QObject
{
    // Q_OBJECT 是 Qt 的宏，必须写在类开头。
    // 它让这个类支持信号和槽机制（跨线程通信的核心）。
    Q_OBJECT

public:
    // 构造函数：传入本地端口、对方IP、对方端口
    DTLSWorker(int localPort, const QString &peerIP, int peerPort);
    // 析构函数：清理 SSL 对象、上下文、关闭套接字
    ~DTLSWorker();

    // 获取对方信息（供主界面显示用）
    QString peerIP() const { return m_peerIP; }
    int peerPort() const { return m_peerPort; }

    // 主动停止工作线程。
    // 原理：把 running 设为 false，接收循环检测到后会自动退出。
    void stop() { running = false; }

    // ============================================================
    // public slots（公开槽函数）
    // 槽函数可以用两种方式调用：
    // 1. 直接调用：worker->connectToPeer()
    // 2. 通过信号连接：当 QThread::started 信号发出时自动调用
    // ============================================================

    // 建立 DTLS 连接（包含 UDP 绑定、SSL 握手、接收循环）
    // 这个函数执行时间很长，必须在后台线程中运行。
    void connectToPeer();

    // 发送数据到对方
    // 跨线程调用时需要用 QMetaObject::invokeMethod + QueuedConnection
    void sendData(const QByteArray &data);

    // ============================================================
    // signals（信号）
    // 信号是一种特殊的函数，不需要实现（Qt 自动生成代码）。
    // 当信号被 emit（发射）时，所有连接到它的槽函数会被执行。
    // 跨线程时，信号通过事件队列安全传递（QueuedConnection）。
    // ============================================================
signals:
    // 连接建立成功后发射
    void connected();
    // 发生错误时发射，msg 是错误描述
    void errorOccurred(const QString &msg);
    // 收到对方消息时发射，text 是收到的文本
    void dataReceived(const QString &text);

private:
    // ============================================================
    // 成员变量
    // ============================================================
    int m_localPort;      // 本机绑定的端口号
    QString m_peerIP;     // 对方的 IP 地址（字符串）
    int m_peerPort;       // 对方的端口号

    // OpenSSL 对象指针
    SSL *ssl = nullptr;     // SSL 连接对象（代表一条 DTLS 连接）
    SSL_CTX *ctx = nullptr; // SSL 上下文（证书、方法等配置）

    // 套接字描述符（Windows 上是 SOCKET 类型，用 qintptr 保存）
    qintptr sockfd = -1;

    // 运行标志。true 时接收循环持续运行，false 时退出循环。
    bool running = false;
};

// ============================================================
// PeerEntry 结构体
// 记录一个"对方"的所有信息：
// - IP 地址和端口号（由用户在界面添加）
// - 对应的 DTLSWorker 和 QThread 指针
//   （"启动所有连接"时创建，连接失败或删除时销毁）
// ============================================================
struct PeerEntry {
    QString ip;              // 对方 IP（如 "192.168.1.101"）
    int port;                // 对方端口（如 9000）
    DTLSWorker *worker = nullptr;  // 负责此连接的 worker（nullptr 表示未连接）
    QThread *thread = nullptr;     // worker 所在的线程（nullptr 表示未连接）
};

// ============================================================
// MainWindow 类
// 主界面窗口，继承 QMainWindow。
// 功能：显示和管理对方列表、启动/停止连接、收发消息。
// ============================================================
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    // 构造函数：创建界面控件、初始化 OpenSSL
    MainWindow(QWidget *parent = nullptr);
    // 析构函数：清理所有连接和线程
    ~MainWindow();

    // ============================================================
    // private slots（私有槽函数）
    // 这些槽函数通常连接界面按钮的 clicked 信号。
    // ============================================================
private slots:
    void addPeer();          // 点击"添加"按钮：将 IP:端口 加入列表
    void removePeer();       // 点击"删除"按钮：移除选中的对方
    void startAll();         // 点击"启动所有连接"：逐个建立 DTLS 连接
    void sendData();         // 点击"发送"：将消息发给所有已连的对方

private:
    // 刷新对方表格的显示（更新状态列）
    void updateTable();

    // ============================================================
    // 界面控件指针
    // ============================================================
    QLineEdit *ed_basePort;   // 本机基端口输入框（第1个对方用 basePort+0，第2个用 basePort+1...）
    QLineEdit *ed_addIP;      // 添加对方时的 IP 输入框
    QLineEdit *ed_addPort;    // 添加对方时的端口输入框
    QTableWidget *table_peers; // 显示所有对方的表格（IP、端口、状态三列）
    QTextEdit *txt_recv;      // 接收消息显示区（只读）
    QLineEdit *ed_send;       // 发送消息输入框

    // 存储所有对方的列表（可动态增删）
    QList<PeerEntry> m_peers;
};

#endif // MAINWINDOW_H
