#pragma once

#include <cstdint>

class Timer {
public:
    Timer(uint32_t durationMs = 10000);
    void start();
    void pause();
    void reset();
    void setDuration(uint32_t durationMs);
    uint32_t getRemaining();
    bool isRunning() const;
    bool isFinished();
private:
    uint32_t duration;
    uint32_t endTime;
    uint32_t remaining;
    bool running;
};