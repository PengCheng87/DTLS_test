#ifndef MAINWINDOW_H
#define MAINWINDOW_H

// ============================================================
// Qt 头文件说明
// ============================================================
#include <QMainWindow>       // 窗口框架（菜单栏、状态栏、工具栏等）
#include <QPushButton>       // 按钮控件
#include <QLineEdit>         // 单行文本输入框
#include <QTextEdit>         // 多行文本显示/编辑框
#include <QTableWidget>      // 表格控件（显示对方列表）
#include <QList>             // 动态数组（存储多个对方信息）

// Qt 网络相关类
#include <QUdpSocket>        // UDP 套接字（替代原始 socket() / bind()）
#include <QDtls>             // Qt 内置 DTLS 类（替代 OpenSSL 的 SSL_* API）
#include <QSslConfiguration> // SSL/TLS/DTLS 配置（证书、密钥等）
#include <QSslCertificate>   // X.509 证书加载
#include <QSslKey>           // 私钥加载
#include <QSslSocket>        // 提供 QSslSocket::SslMode 枚举（ClientMode / ServerMode）

// ============================================================
// DTLSWorker 类
// 负责与"一个"对方建立 DTLS 加密连接并进行网络通信。
// 每个 DTLSWorker 对象专门管理一条连接，内部使用 QUdpSocket 和 QDtls。
// 如果要连接多个对方，就需要创建多个 DTLSWorker。
//
// 注意：与旧版不同，现在不需要 QThread 了！
// 原因：QDtls 的所有操作（握手、收发）都是非阻塞的，
//       通过 Qt 信号槽驱动，不会卡住主界面。
// ============================================================
class DTLSWorker : public QObject
{
    Q_OBJECT

public:
    // 构造函数：传入本地端口、对方IP、对方端口
    DTLSWorker(int localPort, const QString &peerIP, int peerPort);
    // 析构函数：清理 QUdpSocket 和 QDtls 对象
    ~DTLSWorker();

    // 获取对方信息（供主界面显示用）
    QString peerIP() const { return m_peerIP; }
    int peerPort() const { return m_peerPort; }

    // 建立 DTLS 连接（非阻塞，立即返回）
    // 函数内部创建 QUdpSocket 并启动 DTLS 握手，
    // 握手完成后通过 connected() 信号通知主界面。
    void connectToPeer();

    // 发送数据到对方
    void sendData(const QByteArray &data);

signals:
    // 连接建立成功后发射
    void connected();
    // 发生错误时发射，msg 是错误描述
    void errorOccurred(const QString &msg);
    // 收到对方消息时发射，text 是收到的文本
    void dataReceived(const QString &text);

private slots:
    // 当 QUdpSocket 收到 UDP 数据包时自动调用
    // 作用：根据握手状态，转发给 doHandshake() 或 decryptDatagram()
    void onReadyRead();
    // 当 DTLS 握手超时时自动调用
    void onHandshakeTimeout();

private:
    // ============================================================
    // 成员变量
    // ============================================================
    int m_localPort;      // 本机绑定的端口号
    QString m_peerIP;     // 对方的 IP 地址（字符串）
    int m_peerPort;       // 对方的端口号

    // 自动协商的角色（true=服务端, false=客户端）
    // 由 connectToPeer() 设置，onReadyRead() 中会用到
    bool m_isServer = false;

    // QUdpSocket：Qt 封装的 UDP 套接字
    // 替代了旧代码中的 SOCKET + bind() + select()
    // readyRead 信号在有数据到达时自动触发
    QUdpSocket *m_socket = nullptr;

    // QDtls：Qt 封装的 DTLS 连接对象
    // 替代了旧代码中的 SSL* + SSL_CTX* + BIO*
    // 内部包含证书、密钥、加密状态等
    QDtls *m_dtls = nullptr;
};

// ============================================================
// PeerEntry 结构体
// 记录一个"对方"的所有信息：
// - IP 地址和端口号（由用户在界面添加）
// - 对应的 DTLSWorker 指针（启动连接时创建，失败或删除时销毁）
//
// 注意：旧版本还有 QThread *thread，现在不需要了。
// ============================================================
struct PeerEntry {
    QString ip;                      // 对方 IP（如 "192.168.1.101"）
    int port;                        // 对方端口（如 9000）
    DTLSWorker *worker = nullptr;    // 负责此连接的 worker（nullptr 表示未连接）
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
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void addPeer();          // 点击"添加"按钮：将 IP:端口 加入列表
    void removePeer();       // 点击"删除"按钮：移除选中的对方
    void startAll();         // 点击"启动所有连接"：逐个建立 DTLS 连接
    void sendData();         // 点击"发送"：将消息发给所有已连的对方

private:
    void updateTable();      // 刷新对方表格的显示（更新状态列）

    // ============================================================
    // 界面控件指针
    // ============================================================
    QLineEdit *ed_basePort;   // 本机基端口输入框
    QLineEdit *ed_addIP;      // 添加对方时的 IP 输入框
    QLineEdit *ed_addPort;    // 添加对方时的端口输入框
    QTableWidget *table_peers; // 显示所有对方的表格（IP、端口、状态三列）
    QTextEdit *txt_recv;      // 接收消息显示区（只读）
    QLineEdit *ed_send;       // 发送消息输入框

    // 存储所有对方的列表（可动态增删）
    QList<PeerEntry> m_peers;
};

#endif // MAINWINDOW_H
