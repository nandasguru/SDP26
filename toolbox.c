#include <stdio.h>
#include <math.h>
#include "esp_sleep.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define PRESENT 1
#define CONFLICT 2
#define UNKNOWN 3
#define ABSENT 4

#define TOLERANCE 5.0

unsigned long tool_rfid = 2847104201UL;
float tool_weight = 250.0;

int toolbox_check(unsigned long rfid, float weight) {

    if (rfid == tool_rfid && fabs(weight - tool_weight) < TOLERANCE) {
        return PRESENT;
    }
    else if (rfid == tool_rfid && fabs(weight - tool_weight) >= TOLERANCE) {
        return CONFLICT;
    }
    else if (rfid != tool_rfid && fabs(weight - tool_weight) < TOLERANCE) {
        return UNKNOWN;
    }
    else {
        return ABSENT;
    }
}

void app_main(void) {

    unsigned long read_rfid = 2847104201UL;
    float read_weight = 250.0;

    int status = toolbox_check(read_rfid, read_weight);

    printf("Tool status = %d\n", status);

    printf("Going to sleep...\n");
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    esp_deep_sleep_start();
}
