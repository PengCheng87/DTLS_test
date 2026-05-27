#include "mainwindow.h"
#include <QApplication>
#include <QSslSocket>   // 用于选择 SSL 后端
#include <QMessageBox>  // 错误提示

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // Windows 上 Qt 默认使用 Schannel（不兼容 DTLS）
    // 需要强制使用 OpenSSL 后端才能使 QDtls 正常工作
    QStringList backends = QSslSocket::availableBackends();
    if (!backends.contains("openssl")) {
        QMessageBox::critical(nullptr, "SSL 后端错误",
            "未找到 OpenSSL TLS 后端！\n\n"
            "请确认程序目录下的 tls/qopensslbackend.dll 存在。\n"
            "当前可用后端: " + backends.join(", "));
        return 1;
    }
    QSslSocket::setActiveBackend("openssl");

    MainWindow w;
    w.show();
    return a.exec();
}