#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include "esp_sleep.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define PRESENT 1
#define CONFLICT 2
#define UNKNOWN 3
#define ABSENT 4
#define TOLERANCE 5.0
#define MAX_SLOTS 10

typedef enum {
    TOOL_IN = 0,
    TOOL_OUT = 1
} tool_state_t;

// Each slot expects a specific tool
typedef struct {
    uint32_t expected_rfid;
    float expected_weight;
    tool_state_t state;
} slot_t;

// Example: two slots
slot_t slots[MAX_SLOTS] = {
    {2847104201UL, 250.0, TOOL_OUT}, // Slot 0 expects this tool
    {1234567890UL, 150.0, TOOL_OUT}  // Slot 1 expects another tool
};
int slot_count = 2;

// Check the status of a tool placed in a specific slot
int toolbox_check(int slot_index, uint32_t rfid, float weight)
{
    if (slot_index < 0 || slot_index >= slot_count) return ABSENT;

    slot_t *s = &slots[slot_index];

    if (rfid == s->expected_rfid && fabs(weight - s->expected_weight) < TOLERANCE)
        return PRESENT;
    else if (rfid == s->expected_rfid && fabs(weight - s->expected_weight) >= TOLERANCE)
        return CONFLICT;
    else if (rfid != s->expected_rfid && fabs(weight - s->expected_weight) < TOLERANCE)
        return UNKNOWN;
    else
        return ABSENT;
}

// Update the inventory state of a slot
void update_inventory(int slot_index, uint32_t rfid, float weight)
{
    if (slot_index < 0 || slot_index >= slot_count) return;

    slot_t *s = &slots[slot_index];

    int status = toolbox_check(slot_index, rfid, weight);
    if (status == PRESENT)
        s->state = TOOL_IN;
    else
        s->state = TOOL_OUT;
}

// Print the full inventory snapshot
void print_inventory()
{
    printf("Inventory Status:\n");
    for (int i = 0; i < slot_count; i++)
    {
        printf("Slot %d: ", i);
        if (slots[i].state == TOOL_IN)
            printf("IN\n");
        else
            printf("OUT\n");
    }
}

void app_main(void) {
    // Test values for slot 0
    int slot_index = 0;
    uint32_t read_rfid = 2847104201UL;
    float read_weight = 250.0;

    int status = toolbox_check(slot_index, read_rfid, read_weight);
    printf("Slot %d tool status = %d\n", slot_index, status);

    // Update inventory for this slot
    update_inventory(slot_index, read_rfid, read_weight);

    // Print full inventory
    print_inventory();

    printf("Going to sleep...\n");
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    esp_deep_sleep_start();
}