#include "Timer.h"

extern uint32_t currentTime;

Timer::Timer(uint32_t durationMs) : duration(durationMs), endTime(0), remaining(durationMs), running(false) {
}

void Timer::setDuration(uint32_t durationMs) {
    duration = durationMs;
    remaining = durationMs;
    running = false;
}

void Timer::start() {
    if (!running) {
        endTime = currentTime + remaining;
        running = true;
    }
}

void Timer::pause() {
    if (running) {
        if (currentTime >= endTime) {
            remaining = 0;
        } else {
            remaining = endTime - currentTime;
        }
        running = false;
    }
}

void Timer::reset() {
    running = false;
    remaining = duration;
}

uint32_t Timer::getRemaining() {
    if (running) {
        if (currentTime >= endTime) {
            running = false;
            remaining = 0;
        } else {
            remaining = endTime - currentTime;
        }
    }
    return remaining;
}

bool Timer::isRunning() const {
    return running;
}

bool Timer::isFinished() {
    return getRemaining() == 0;
}