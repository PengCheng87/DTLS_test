@echo off
set PATH=C:\msys64\ucrt64\bin;%PATH%
cd /d "C:\Users\Administrator\Documents\Software Engineering\DTLS_test\release"
g++ -std=c++17 main.o mainwindow.o moc_mainwindow.o -LC:/msys64/ucrt64/lib -lQt6Core -lQt6Gui -lQt6Widgets -lQt6Network -o DTLS_P2P.exe
echo exit code: %ERRORLEVEL%
