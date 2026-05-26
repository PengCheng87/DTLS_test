QT += core gui network widgets

CONFIG += c++17

SOURCES += \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    mainwindow.h

LIBS += -lssl -lcrypto -lws2_32