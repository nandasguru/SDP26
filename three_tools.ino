// =============================
// ADD THIS AT TOP (NEW)
// =============================
#define NUM_TOOLS 3

// TODO: adjust SS pins later
int SS_PINS[NUM_TOOLS] = {4, 5, 18};

// Replace single reader with array
MFRC522 rfid[NUM_TOOLS] = {
  MFRC522(SS_PINS[0], RST_PIN),
  MFRC522(SS_PINS[1], RST_PIN),
  MFRC522(SS_PINS[2], RST_PIN)
};

// =============================
// REPLACE SINGLE STATE (OLD)
// ToolState currentToolState;
// =============================

ToolState toolStates[NUM_TOOLS];
unsigned long lastValidRfidTimeArr[NUM_TOOLS];

// =============================
// SETUP CHANGES
// =============================
void setup() {
  Serial.begin(115200);
  delay(500);

  pinMode(LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  SPI.begin();

  // INIT ALL RFID READERS
  for (int i = 0; i < NUM_TOOLS; i++) {
    rfid[i].PCD_Init();
    toolStates[i] = ABSENT_VALID;
    lastValidRfidTimeArr[i] = 0;
  }

  Serial.println("=== 3 TOOL SYSTEM READY ===");
}

// =============================
// NEW: PER-TOOL RFID CHECK
// =============================
bool checkRFIDTool(int i) {
  if (!rfid[i].PICC_IsNewCardPresent()) return false;
  if (!rfid[i].PICC_ReadCardSerial()) return false;

  Serial.print("[RFID] Tool ");
  Serial.print(i);
  Serial.println(" detected");

  lastValidRfidTimeArr[i] = millis();

  rfid[i].PICC_HaltA();
  rfid[i].PCD_StopCrypto1();

  return true;
}

// =============================
// SIMPLIFIED WEIGHT (TEMP)
// =============================
float readWeight() {
  // TODO: replace with real load cell
  return 1000.0;
}

// Example tool weights
float toolWeights[NUM_TOOLS] = {250.0, 150.0, 300.0};
float expectedTotal = 250.0 + 150.0 + 300.0;
#define TOL 20.0

// =============================
// LOOP (UPDATED)
// =============================
void loop() {
  unsigned long currentTime = millis();

  // -------- RFID CHECK --------
  for (int i = 0; i < NUM_TOOLS; i++) {
    checkRFIDTool(i);
  }

  // -------- WEIGHT CHECK --------
  float currentWeight = readWeight();
  float diff = expectedTotal - currentWeight;

  int weightMatch = -1;
  for (int i = 0; i < NUM_TOOLS; i++) {
    if (fabs(diff - toolWeights[i]) < TOL) {
      weightMatch = i;
    }
  }

  // -------- STATE UPDATE --------
  for (int i = 0; i < NUM_TOOLS; i++) {

    bool rfidValid = (currentTime - lastValidRfidTimeArr[i]) < RFID_VALID_WINDOW;

    if (rfidValid) {
      toolStates[i] = PRESENT_VALID;
    } else {
      toolStates[i] = ABSENT_VALID;
    }

    // refine using weight
    if (!rfidValid && weightMatch == i) {
      toolStates[i] = ABSENT_VALID;
    }
  }

  // -------- PRINT STATUS --------
  Serial.println("---- STATUS ----");

  for (int i = 0; i < NUM_TOOLS; i++) {
    Serial.print("Tool ");
    Serial.print(i);
    Serial.print(": ");

    switch(toolStates[i]) {
      case PRESENT_VALID:
        Serial.println("IN");
        break;
      case ABSENT_VALID:
        Serial.println("OUT");
        break;
      default:
        Serial.println("ERR");
        break;
    }
  }

  Serial.print("Weight diff: ");
  Serial.println(diff);

  Serial.println("----------------\n");

  delay(200);
}