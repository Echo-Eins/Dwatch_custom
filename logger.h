#ifndef LOGGER_H
#define LOGGER_H

#include <Arduino.h>
#include <FS.h>

class LoggerClass {
public:
    bool begin();
    void log(const char* event);
    void flush();
    void end();
    bool isEnabled() const { return sdAvailable; }

private:
    bool sdAvailable = false;
    File logFile;
    char fileName[32];
};

extern LoggerClass Logger;

#endif // LOGGER_H