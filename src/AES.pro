QT += widgets

CONFIG += c++11

HEADERS += \
    MainDialog.h \
    qlightboxwidget.h \
    Global.h \
    KeyLineValidator.h \
    AESArrays.h \
    AESCipher.h \
    MD5.h \
    AESAsync.h \
    RemFile.h

SOURCES += \
    MainDialog.cpp \
    qlightboxwidget.cpp \
    main.cpp \
    AESCipher.cpp \
    AESAsync.cpp

RESOURCES += \
    R.qrc
