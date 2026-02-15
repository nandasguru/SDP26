#include <stdio.h>
#include <math.h>

#define PRESENT 1
#define CONFLICT 2
#define UNKNOWN 3
#define ABSENT 4

unsigned long tool_rfid = 2847104201;     // Random RFID Tag
float tool_weight = 250;                  // Random Tool Weight (grams)
#define TOLERANCE 5.0

int toolbox_check(int rfid, float weight) {
    if (rfid == tool_rfid && fabs(weight - tool_weight) < TOLERANCE){
        return PRESENT;
    } else if (rfid == tool_rfid && fabs(weight - tool_weight) < TOLERANCE){
        return CONFLICT;
    } else if (rfid != tool_rfid && fabs(weight - tool_weight) < TOLERANCE){
        return UNKNOWN;
    } else {
        return ABSENT;
    }
}

