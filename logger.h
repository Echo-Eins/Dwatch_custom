#ifndef LOGGER_H
#define LOGGER_H

#include <Arduino.h>

#if defined(ESP8266) || defined(ESP32)
#include <FS.h>
using LoggerFile = fs::File;
#else
#include <SD.h>
using LoggerFile = File;
#endif

class LoggerClass {
public:
    bool begin();
    void log(const char* event);
    void flush();
    void end();
    bool isEnabled() const { return sdAvailable; }

private:
    bool sdAvailable = false;
    LoggerFile logFile;
    char fileName[32];
};

extern LoggerClass Logger;

#endif // LOGGER_H