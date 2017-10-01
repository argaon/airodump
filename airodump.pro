TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    mac.cpp

HEADERS += \
    80211header.h \
    wlan_key_value.h \
    mac.h

