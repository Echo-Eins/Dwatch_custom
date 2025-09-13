#pragma once
#include "Arduino.h"

class Calculator {
public:
    void clear();
    void inputDigit(uint8_t digit);
    void setOperation(char op);
    String getDisplay() const;
private:
    long current = 0;
    long previous = 0;
    char operation = 0;
};