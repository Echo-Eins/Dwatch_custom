#include "logger.h"

#if defined(ESP8266)
#include <SDFS.h>
#define LOGGER_SD SDFS
#else
#include <SD.h>
#define LOGGER_SD SD
#endif
#include <SPI.h>

static uint32_t getFreeMem() {
#if defined(ESP8266) || defined(ESP32)
    return ESP.getFreeHeap();
#else
    return 0;
#endif
}

LoggerClass Logger;

bool LoggerClass::begin() {
    sdAvailable = LOGGER_SD.begin();
    if (!sdAvailable) {
        Serial.println("[LOGGER] SD init failed");
        return false;
    }

    unsigned long t = millis();
    snprintf(fileName, sizeof(fileName), "/log_%lu.txt", t);
    logFile = LOGGER_SD.open(fileName, FILE_WRITE);
    if (!logFile) {
        Serial.println("[LOGGER] file open failed");
        sdAvailable = false;
        return false;
    }

    char line[80];
    snprintf(line, sizeof(line), "0 | Boot start | free_mem=%lu", (unsigned long)getFreeMem());
    logFile.println(line);
    logFile.flush();
    return true;
}

void LoggerClass::log(const char* event) {
    unsigned long t = millis();
    char line[128];
    snprintf(line, sizeof(line), "%lu | %s | free_mem=%lu", t, event, (unsigned long)getFreeMem());
    if (sdAvailable && logFile) {
        logFile.println(line);
    } else {
        Serial.println(line);
    }
}

void LoggerClass::flush() {
    if (sdAvailable && logFile) {
        logFile.flush();
    }
}

void LoggerClass::end() {
    if (sdAvailable && logFile) {
        logFile.flush();
        logFile.close();
    }
}