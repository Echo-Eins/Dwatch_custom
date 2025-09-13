#include "Calculator.h"

void Calculator::clear() {
    current = 0;
    previous = 0;
    operation = 0;
}

void Calculator::inputDigit(uint8_t digit) {
    current = current * 10 + digit;
}

void Calculator::setOperation(char op) {
    if (op == 'C') {
        clear();
        return;
    }
    if (operation == 0) {
        // first operation
        previous = current;
        current = 0;
        operation = op == '=' ? 0 : op;
        if (op == '=') {
            // nothing to calculate yet
            current = previous;
        }
        return;
    }
    // compute previous operation
    switch (operation) {
        case '+': previous += current; break;
        case '-': previous -= current; break;
        case '*': previous *= current; break;
        case '/':
            if (current != 0) previous /= current;
            else previous = 0;
            break;
    }
    current = 0;
    if (op == '=') {
        operation = 0;
        current = previous;
    } else {
        operation = op;
    }
}

String Calculator::getDisplay() const {
    if (operation == 0) {
        return String(current);
    }
    return String(previous) + operation + String(current);
}