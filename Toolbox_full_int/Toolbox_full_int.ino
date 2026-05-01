#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Preferences.h>
#include "HX711.h"

// ============================================================
// BLE INCLUDES
// ============================================================
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <BLESecurity.h>

// Crypto for HMAC
#include "mbedtls/md.h"
#include "esp_system.h"

// ============================================================
// BLE CONFIGURATION
// ============================================================
#define BLE_SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define BLE_CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

BLECharacteristic *pCharacteristic = nullptr;
bool bleDeviceConnected = false;
String bleLastReceivedMessage = "";
volatile bool bleLinkEncrypted = false;

// ============================================================
// PIN DEFINITIONS
// ============================================================
#define SS_PIN_TOOLS     4
#define SS_PIN_USERS     5
#define SS_PIN_PROVISION 15
#define RST_PIN          17

// ============================================================
// DISPLAY SETUP
// ============================================================
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// ============================================================
// RFID READERS
// ============================================================
MFRC522 rfidTools(SS_PIN_TOOLS, RST_PIN);
MFRC522 rfidUsers(SS_PIN_USERS, RST_PIN);
MFRC522 rfidProvision(SS_PIN_PROVISION, RST_PIN);

// ============================================================
// USERS
// ============================================================
#define NUM_USERS 2
struct User {
  const char* name;
  uint8_t uid[4];
};

User users[NUM_USERS] = {
  { "Bob",   {0x23, 0xBF, 0xE8, 0x39} },
  { "Alice", {0x03, 0xCC, 0x2B, 0x3A} }
};

// ============================================================
// TOOLS
// ============================================================
#define NUM_TOOLS 3
struct Tool {
  const char* name;
  uint8_t uid[4];
  bool present;
  const char* checkedOutBy;
  float weightGrams;  // Expected weight of this tool in grams
                      // TODO: fill in real values after calibration
                      // e.g. weigh each tool on a kitchen scale
};

Tool tools[NUM_TOOLS] = {
  //  name      uid                              present  checkedOutBy  weightGrams
  { "Tool1", {0x02, 0x1D, 0xB3, 0xAB}, true,  nullptr,  100.0f },  // TODO: replace 100.0
  { "Tool2", {0xB2, 0x27, 0x9D, 0xAB}, true,  nullptr,  200.0f },  // TODO: replace 200.0
  { "Tool3", {0xC2, 0x66, 0xBB, 0xAB}, true,  nullptr,  300.0f },  // TODO: replace 300.0
};

// ============================================================
// SESSION STATE
// ============================================================
bool sessionActive = false;
User* currentUser = nullptr;
int sessionToolsTouched[NUM_TOOLS];
int sessionToolCount = 0;

// ============================================================
// DEBOUNCE + AUTO-LOGOUT TIMER
// ============================================================
unsigned long lastUserScan = 0;
#define USER_SCAN_DEBOUNCE_MS 1500
unsigned long sessionStartTime = 0;
#define SESSION_TIMEOUT_MS 10000

// ============================================================
// LOAD CELL (HX711)
// ============================================================
#define LOADCELL_DOUT_PIN 32
#define LOADCELL_SCK_PIN  33

// ---------------------------------------------------------------
// CALIBRATION FACTOR — how to find yours:
//   1. Flash this code with CALIBRATION_FACTOR = 1.0
//   2. Open Serial Monitor, tare the scale (all tools in box)
//   3. Place a known weight (e.g. 500g) on the scale
//   4. Note the raw reading printed
//   5. CALIBRATION_FACTOR = raw_reading / known_weight_in_grams
//   6. Replace the value below and reflash
// ---------------------------------------------------------------
#define CALIBRATION_FACTOR 1.0f   // TODO: replace after calibration

// Weight tolerance: how many grams of error is acceptable.
// ±15% of expected weight change is a reasonable starting point.
// Tighten this after real testing if you want stricter checks.
#define WEIGHT_TOLERANCE_PERCENT 15.0f

HX711 scale;

// Tracks the last known stable weight (updated after each
// successful checkout or return). Initialized after tare in setup().
float scaleBaselineGrams = 0.0f;

// How many readings to average for a stable measurement
#define SCALE_NUM_READINGS 10

// Window in ms to wait for user to place tool back after return scan
#define RETURN_WEIGHT_WINDOW_MS 4000

float scaleRead() {
  if (!scale.is_ready()) return scaleBaselineGrams; // fall back if not ready
  return scale.get_units(SCALE_NUM_READINGS);
}

// Returns true if actual delta is within tolerance of expected delta
bool weightDeltaMatches(float expectedDeltaGrams, float actualDeltaGrams) {
  float tolerance = abs(expectedDeltaGrams) * (WEIGHT_TOLERANCE_PERCENT / 100.0f);
  return abs(actualDeltaGrams - expectedDeltaGrams) <= tolerance;
}

// Sum the weights of all tools currently marked as checked out
float sumCheckedOutWeight() {
  float total = 0.0f;
  for (int i = 0; i < NUM_TOOLS; i++) {
    if (!tools[i].present) total += tools[i].weightGrams;
  }
  return total;
}

// BLE weight event senders (declared here, defined after BLE setup)
void BLE_sendWeightMismatch(float expected, float actual);
void BLE_sendUnauthorizedRemoval(float delta);

// ============================================================
// RFID SECURITY
// ============================================================
static const uint8_t RFID_RECORD_BLOCK  = 4;
static const uint8_t RFID_TRAILER_BLOCK = 7;

Preferences prefRfid;
static const char* RFID_PREF_NS = "rfid-sec";

uint8_t g_sectorKey6[6];
uint8_t g_masterHmacKey[32];
bool g_refuseDefaultKey = true;

bool isAllFF(const uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; i++) if (buf[i] != 0xFF) return false;
  return true;
}
bool isAll00(const uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; i++) if (buf[i] != 0x00) return false;
  return true;
}
void fillRandom(uint8_t* out, size_t len) {
  size_t i = 0;
  while (i < len) {
    uint32_t r = esp_random();
    for (int b = 0; b < 4 && i < len; b++, i++) out[i] = (uint8_t)((r >> (8 * b)) & 0xFF);
  }
}

bool rfidSecurityInitKeys() {
  prefRfid.begin(RFID_PREF_NS, false);

  size_t klen = prefRfid.getBytesLength("sectorKey6");
  if (klen == 6) {
    prefRfid.getBytes("sectorKey6", g_sectorKey6, 6);
  } else {
    do { fillRandom(g_sectorKey6, 6); } while (isAllFF(g_sectorKey6, 6));
    prefRfid.putBytes("sectorKey6", g_sectorKey6, 6);
  }

  size_t hlen = prefRfid.getBytesLength("hmacKey32");
  if (hlen == 32) {
    prefRfid.getBytes("hmacKey32", g_masterHmacKey, 32);
  } else {
    do { fillRandom(g_masterHmacKey, 32); } while (isAll00(g_masterHmacKey, 32) || isAllFF(g_masterHmacKey, 32));
    prefRfid.putBytes("hmacKey32", g_masterHmacKey, 32);
  }

  if (g_refuseDefaultKey && isAllFF(g_sectorKey6, 6)) {
    Serial.println("[RFID] ERROR: default sector key detected; refusing.");
    return false;
  }
  Serial.println("[RFID] Security keys ready.");
  return true;
}

void hmacTrunc4(const uint8_t key[32], const uint8_t tagId8[8], uint32_t counter, uint8_t out4[4]) {
  uint8_t msg[12];
  memcpy(msg, tagId8, 8);
  msg[8]  = (uint8_t)(counter & 0xFF);
  msg[9]  = (uint8_t)((counter >> 8) & 0xFF);
  msg[10] = (uint8_t)((counter >> 16) & 0xFF);
  msg[11] = (uint8_t)((counter >> 24) & 0xFF);

  uint8_t full[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(info, key, 32, msg, sizeof(msg), full);
  memcpy(out4, full, 4);
}

bool mifareAuthBlock(MFRC522 &reader, uint8_t blockAddr, const uint8_t key6[6], bool useKeyB) {
  MFRC522::MIFARE_Key key;
  memcpy(key.keyByte, key6, 6);
  MFRC522::StatusCode status = reader.PCD_Authenticate(
    useKeyB ? MFRC522::PICC_CMD_MF_AUTH_KEY_B : MFRC522::PICC_CMD_MF_AUTH_KEY_A,
    blockAddr, &key, &(reader.uid)
  );
  return (status == MFRC522::STATUS_OK);
}

bool mifareRead16(MFRC522 &reader, uint8_t blockAddr, uint8_t out16[16]) {
  byte buffer[18];
  byte size = sizeof(buffer);
  MFRC522::StatusCode status = reader.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) return false;
  memcpy(out16, buffer, 16);
  return true;
}

bool mifareWrite16(MFRC522 &reader, uint8_t blockAddr, const uint8_t in16[16]) {
  MFRC522::StatusCode status = reader.MIFARE_Write(blockAddr, (byte*)in16, 16);
  return (status == MFRC522::STATUS_OK);
}

void buildTrailerBlock(uint8_t out16[16], const uint8_t keyA6[6], const uint8_t keyB6[6]) {
  memcpy(&out16[0], keyA6, 6);
  out16[6] = 0xFF;
  out16[7] = 0x07;
  out16[8] = 0x80;
  out16[9] = 0x69;
  memcpy(&out16[10], keyB6, 6);
}

void buildRecordBlock(uint8_t out16[16], const uint8_t tagId8[8], uint32_t counter) {
  memset(out16, 0, 16);
  memcpy(&out16[0], tagId8, 8);
  out16[8]  = (uint8_t)(counter & 0xFF);
  out16[9]  = (uint8_t)((counter >> 8) & 0xFF);
  out16[10] = (uint8_t)((counter >> 16) & 0xFF);
  out16[11] = (uint8_t)((counter >> 24) & 0xFF);
  uint8_t mac4[4];
  hmacTrunc4(g_masterHmacKey, tagId8, counter, mac4);
  memcpy(&out16[12], mac4, 4);
}

bool rfidProvisionCurrentToolTag(MFRC522 &reader, uint32_t initialCounter = 0) {
  if (g_refuseDefaultKey && isAllFF(g_sectorKey6, 6)) return false;
  // Note: PICC_IsNewCardPresent() and PICC_ReadCardSerial() already called by caller.

  uint8_t defaultFF[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  if (!mifareAuthBlock(reader, RFID_TRAILER_BLOCK, defaultFF, false)) {
    if (!mifareAuthBlock(reader, RFID_TRAILER_BLOCK, g_sectorKey6, false) &&
        !mifareAuthBlock(reader, RFID_TRAILER_BLOCK, g_sectorKey6, true)) {
      Serial.println("[RFID] Provision: cannot auth trailer.");
      reader.PICC_HaltA(); reader.PCD_StopCrypto1();
      return false;
    }
  }

  uint8_t trailer[16];
  buildTrailerBlock(trailer, g_sectorKey6, g_sectorKey6);
  if (!mifareWrite16(reader, RFID_TRAILER_BLOCK, trailer)) {
    Serial.println("[RFID] Provision: trailer write failed.");
    reader.PICC_HaltA(); reader.PCD_StopCrypto1();
    return false;
  }

  if (!mifareAuthBlock(reader, RFID_RECORD_BLOCK, g_sectorKey6, false) &&
      !mifareAuthBlock(reader, RFID_RECORD_BLOCK, g_sectorKey6, true)) {
    Serial.println("[RFID] Provision: record auth failed.");
    reader.PICC_HaltA(); reader.PCD_StopCrypto1();
    return false;
  }

  uint8_t tagId8[8];
  fillRandom(tagId8, 8);
  uint8_t record[16];
  buildRecordBlock(record, tagId8, initialCounter);

  if (!mifareWrite16(reader, RFID_RECORD_BLOCK, record)) {
    Serial.println("[RFID] Provision: record write failed.");
    reader.PICC_HaltA(); reader.PCD_StopCrypto1();
    return false;
  }

  Serial.println("[RFID] Provision OK.");
  reader.PICC_HaltA();
  reader.PCD_StopCrypto1();
  return true;
}

bool rfidAuthorizeAndUpdate(MFRC522 &reader) {
  if (g_refuseDefaultKey && isAllFF(g_sectorKey6, 6)) return false;

  if (!mifareAuthBlock(reader, RFID_RECORD_BLOCK, g_sectorKey6, false) &&
      !mifareAuthBlock(reader, RFID_RECORD_BLOCK, g_sectorKey6, true)) {
    return false;
  }

  uint8_t block[16];
  if (!mifareRead16(reader, RFID_RECORD_BLOCK, block)) return false;
  if (isAll00(block, 16) || isAllFF(block, 16)) return false;

  uint8_t tagId8[8];
  memcpy(tagId8, &block[0], 8);
  uint32_t counter =
    ((uint32_t)block[8]) |
    ((uint32_t)block[9]  << 8) |
    ((uint32_t)block[10] << 16) |
    ((uint32_t)block[11] << 24);

  uint8_t macStored[4];
  memcpy(macStored, &block[12], 4);

  uint8_t macExpected[4];
  hmacTrunc4(g_masterHmacKey, tagId8, counter, macExpected);
  if (memcmp(macStored, macExpected, 4) != 0) return false;

  uint8_t updated[16];
  buildRecordBlock(updated, tagId8, counter + 1);
  if (!mifareWrite16(reader, RFID_RECORD_BLOCK, updated)) return false;

  return true;
}

bool authorizeTag(MFRC522::Uid* uid) {
  (void)uid;
  return rfidAuthorizeAndUpdate(rfidTools);
}

// ============================================================
// BLE SECURITY CALLBACKS
// ============================================================
class MySecurityCallbacks : public BLESecurityCallbacks {
  uint32_t onPassKeyRequest() override { return 123456; }
  void onPassKeyNotify(uint32_t pass_key) override {
    Serial.print("[BLE] Passkey: "); Serial.println(pass_key);
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("BLE Passkey:");
    display.println(pass_key);
    display.display();
  }
  bool onConfirmPIN(uint32_t pass_key) override {
    Serial.print("[BLE] ConfirmPIN: "); Serial.println(pass_key);
    return true;
  }
  bool onSecurityRequest() override { return true; }
  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl) override {
    if (cmpl.success) {
      bleLinkEncrypted = true;
      Serial.println("[BLE] Auth complete: encrypted.");
    } else {
      bleLinkEncrypted = false;
      Serial.println("[BLE] Auth failed.");
    }
  }
};

// ============================================================
// BLE CALLBACKS
// ============================================================
class MyBLEServerCallbacks: public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) override {
    bleDeviceConnected = true;
    bleLinkEncrypted = false;
    Serial.println("[BLE] Device connected");
  }
  void onDisconnect(BLEServer* pServer) override {
    bleDeviceConnected = false;
    bleLinkEncrypted = false;
    Serial.println("[BLE] Device disconnected");
    pServer->startAdvertising();
    Serial.println("[BLE] Advertising restarted");
  }
};

class MyBLECharacteristicCallbacks: public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) override {
    if (!bleLinkEncrypted) {
      Serial.println("[BLE] Reject write: link not encrypted.");
      return;
    }
    String value = pCharacteristic->getValue().c_str();
    if (value.length() > 0) {
      bleLastReceivedMessage = value;
      Serial.print("[BLE] Received: ");
      Serial.println(bleLastReceivedMessage);
    }
  }
};

// ============================================================
// BLE INIT
// ============================================================
void BLE_init_secure() {
  Serial.println("[BLE] Initializing (secure)...");
  BLEDevice::init("SmartToolbox");

  BLESecurity *pSecurity = new BLESecurity();
  pSecurity->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_MITM_BOND);
  pSecurity->setCapability(ESP_IO_CAP_OUT);
  pSecurity->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
  BLEDevice::setSecurityCallbacks(new MySecurityCallbacks());

  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyBLEServerCallbacks());

  BLEService *pService = pServer->createService(BLE_SERVICE_UUID);

  pCharacteristic = pService->createCharacteristic(
    BLE_CHARACTERISTIC_UUID,
    BLECharacteristic::PROPERTY_READ   |
    BLECharacteristic::PROPERTY_WRITE  |
    BLECharacteristic::PROPERTY_NOTIFY |
    BLECharacteristic::PROPERTY_INDICATE
  );

  pCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ_ENCRYPTED | ESP_GATT_PERM_WRITE_ENCRYPTED);
  pCharacteristic->setCallbacks(new MyBLECharacteristicCallbacks());
  pCharacteristic->addDescriptor(new BLE2902());

  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(BLE_SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);
  pAdvertising->setMinPreferred(0x12);
  BLEDevice::startAdvertising();

  Serial.println("[BLE] Ready and advertising (secure).");
}

// ============================================================
// BLE HELPERS
// ============================================================
bool BLE_isConnected() { return bleDeviceConnected; }

bool BLE_sendMessage(String message) {
  if (!bleDeviceConnected || pCharacteristic == nullptr) return false;
  if (!bleLinkEncrypted) {
    Serial.println("[BLE] Not sending: link not encrypted yet.");
    return false;
  }
  pCharacteristic->setValue(message);
  pCharacteristic->notify();
  Serial.println("[BLE] Sent: " + message);
  return true;
}

bool BLE_hasNewMessage() { return (bleLastReceivedMessage.length() > 0); }

String BLE_getLastMessage() {
  String msg = bleLastReceivedMessage;
  bleLastReceivedMessage = "";
  return msg;
}

// ============================================================
// BLE EVENT SENDERS
// ============================================================
void BLE_sendLogin(const char* userName) {
  if (!BLE_isConnected()) return;
  BLE_sendMessage("{\"event\":\"login\",\"user\":\"" + String(userName) + "\"}");
}
void BLE_sendLogout(const char* userName) {
  if (!BLE_isConnected()) return;
  BLE_sendMessage("{\"event\":\"logout\",\"user\":\"" + String(userName) + "\"}");
}
void BLE_sendCheckout(const char* userName, const char* toolName) {
  if (!BLE_isConnected()) return;
  BLE_sendMessage("{\"event\":\"checkout\",\"user\":\"" + String(userName) +
                  "\",\"tool\":\"" + String(toolName) + "\"}");
}
void BLE_sendReturn(const char* toolName) {
  if (!BLE_isConnected()) return;
  BLE_sendMessage("{\"event\":\"return\",\"tool\":\"" + String(toolName) + "\"}");
}
void BLE_sendFullInventory() {
  if (!BLE_isConnected()) return;
  String json = "{\"event\":\"inventory\",\"tools\":[";
  for (int i = 0; i < NUM_TOOLS; i++) {
    if (i > 0) json += ",";
    json += "{\"name\":\"" + String(tools[i].name) + "\",";
    json += "\"status\":\"" + String(tools[i].present ? "in" : "out") + "\"";
    if (!tools[i].present && tools[i].checkedOutBy != nullptr)
      json += ",\"user\":\"" + String(tools[i].checkedOutBy) + "\"";
    json += "}";
  }
  json += "]}";
  BLE_sendMessage(json);
}

// Weight mismatch alert sent to app — includes expected vs actual delta
void BLE_sendWeightMismatch(float expected, float actual) {
  if (!BLE_isConnected()) return;
  String json = "{\"event\":\"weight_mismatch\","
                "\"expected_delta\":" + String(expected, 1) + ","
                "\"actual_delta\":" + String(actual, 1) + "}";
  BLE_sendMessage(json);
}

// Sent when scale drops significantly with no active session
void BLE_sendUnauthorizedRemoval(float delta) {
  if (!BLE_isConnected()) return;
  String json = "{\"event\":\"unauthorized_removal\","
                "\"weight_delta\":" + String(delta, 1) + "}";
  BLE_sendMessage(json);
}

// ============================================================
// HELPERS
// ============================================================
int findToolByUID(MFRC522::Uid* uid) {
  if (uid->size != 4) return -1;
  for (int i = 0; i < NUM_TOOLS; i++)
    if (memcmp(uid->uidByte, tools[i].uid, 4) == 0) return i;
  return -1;
}
int findUserByUID(MFRC522::Uid* uid) {
  if (uid->size != 4) return -1;
  for (int i = 0; i < NUM_USERS; i++)
    if (memcmp(uid->uidByte, users[i].uid, 4) == 0) return i;
  return -1;
}
bool alreadyTouchedThisSession(int toolIndex) {
  for (int i = 0; i < sessionToolCount; i++)
    if (sessionToolsTouched[i] == toolIndex) return true;
  return false;
}

// ============================================================
// DISPLAY
// ============================================================
void showDefaultScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("Smart Toolbox");
  display.println("================");
  for (int i = 0; i < NUM_TOOLS; i++) {
    display.print(tools[i].name);
    display.print(": ");
    if (tools[i].present) {
      display.println("IN");
    } else {
      display.print("OUT-");
      display.println(tools[i].checkedOutBy);
    }
  }
  display.display();
}

void showSessionScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.print("Checkout - ");
  display.println(currentUser->name);
  display.println("================");
  if (sessionToolCount == 0) {
    display.println("Scan tools...");
  } else {
    for (int i = 0; i < sessionToolCount; i++)
      display.println(tools[sessionToolsTouched[i]].name);
  }
  display.display();
}

// ============================================================
// SERIAL LOG
// ============================================================
void logAllTools() {
  for (int i = 0; i < NUM_TOOLS; i++) {
    Serial.print("STATUS,");
    Serial.print(tools[i].name);
    Serial.print(",");
    if (tools[i].present) {
      Serial.println("IN");
    } else {
      Serial.print("OUT,");
      Serial.println(tools[i].checkedOutBy);
    }
  }
}

// ============================================================
// SESSION MANAGEMENT
// ============================================================
void startSession(User* user) {
  sessionActive = true;
  currentUser = user;
  sessionToolCount = 0;
  memset(sessionToolsTouched, -1, sizeof(sessionToolsTouched));
  sessionStartTime = millis();

  Serial.print("LOGIN,"); Serial.println(user->name);
  BLE_sendLogin(user->name);
  showSessionScreen();
}

// Called at logout — this is where weight verification happens.
// We compare the expected weight drop (sum of checked-out tools)
// against the actual drop from the baseline.
void endSession() {
  Serial.print("LOGOUT,"); Serial.println(currentUser->name);

  // Only run weight check if any tools were checked out this session
  if (sessionToolCount > 0) {
    float currentWeight = scaleRead();
    float actualDelta   = scaleBaselineGrams - currentWeight;  // positive = weight dropped
    float expectedDelta = 0.0f;
    for (int i = 0; i < sessionToolCount; i++) {
      expectedDelta += tools[sessionToolsTouched[i]].weightGrams;
    }

    Serial.print("[WEIGHT] Baseline: "); Serial.print(scaleBaselineGrams, 1);
    Serial.print("g  Current: ");        Serial.print(currentWeight, 1);
    Serial.print("g  ActualDelta: ");    Serial.print(actualDelta, 1);
    Serial.print("g  ExpectedDelta: ");  Serial.print(expectedDelta, 1); Serial.println("g");

    if (!weightDeltaMatches(expectedDelta, actualDelta)) {
      // Mismatch — show on OLED and alert via BLE
      Serial.println("[WEIGHT] MISMATCH at logout!");

      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Weight Mismatch!");
      display.print("Expected: -"); display.print((int)expectedDelta); display.println("g");
      display.print("Actual:   -"); display.print((int)actualDelta);   display.println("g");
      display.println("Check tools.");
      display.display();
      delay(3000);

      BLE_sendWeightMismatch(expectedDelta, actualDelta);
      // Note: we still complete the logout — the mismatch is logged
      // and flagged but doesn't block the user from leaving.
    } else {
      // Weight checks out — update baseline to reflect tools are gone
      scaleBaselineGrams = currentWeight;
      Serial.println("[WEIGHT] OK at logout. Baseline updated.");
    }
  }

  BLE_sendLogout(currentUser->name);

  sessionActive = false;
  currentUser = nullptr;
  sessionToolCount = 0;

  showDefaultScreen();
  logAllTools();
}

// ============================================================
// HANDLE USER READER
// ============================================================
void handleUserReader() {
  if (!rfidUsers.PICC_IsNewCardPresent()) return;
  if (!rfidUsers.PICC_ReadCardSerial()) return;

  if (millis() - lastUserScan < USER_SCAN_DEBOUNCE_MS) {
    rfidUsers.PICC_HaltA();
    rfidUsers.PCD_StopCrypto1();
    return;
  }
  lastUserScan = millis();

  int userIndex = findUserByUID(&rfidUsers.uid);

  if (userIndex != -1) {
    if (!sessionActive) {
      startSession(&users[userIndex]);
    } else if (currentUser == &users[userIndex]) {
      endSession();
    } else {
      Serial.print("BLOCKED,");
      Serial.print(users[userIndex].name);
      Serial.print(",SESSION_ACTIVE,");
      Serial.println(currentUser->name);

      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Session active!");
      display.print(currentUser->name);
      display.println(" must end");
      display.println("session first.");
      display.display();
      delay(2000);
      showSessionScreen();
    }
  }

  rfidUsers.PICC_HaltA();
  rfidUsers.PCD_StopCrypto1();
}

// ============================================================
// HANDLE TOOL READER
// ============================================================
void handleToolReader() {
  if (!rfidTools.PICC_IsNewCardPresent()) return;
  if (!rfidTools.PICC_ReadCardSerial()) return;

  int toolIndex = findToolByUID(&rfidTools.uid);
  if (toolIndex == -1) {
    rfidTools.PICC_HaltA();
    rfidTools.PCD_StopCrypto1();
    return;
  }

  bool isReturning = !tools[toolIndex].present;

  if (isReturning) {
    // Block returns during an active session
    if (sessionActive) {
      rfidTools.PICC_HaltA();
      rfidTools.PCD_StopCrypto1();
      return;
    }

    // Show a prompt and wait for the user to physically place the tool back.
    // We wait RETURN_WEIGHT_WINDOW_MS ms then check if weight rose correctly.
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Place tool in box");
    display.print(tools[toolIndex].name);
    display.println("...");
    display.display();

    // Halt the card now — we don't need it anymore
    rfidTools.PICC_HaltA();
    rfidTools.PCD_StopCrypto1();

    // Countdown display while waiting
    unsigned long waitStart = millis();
    while (millis() - waitStart < RETURN_WEIGHT_WINDOW_MS) {
      int secsLeft = (RETURN_WEIGHT_WINDOW_MS - (millis() - waitStart)) / 1000 + 1;
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Place tool in box:");
      display.println(tools[toolIndex].name);
      display.print("Waiting... ");
      display.print(secsLeft);
      display.println("s");
      display.display();
      delay(500);
    }

    // Read weight after window
    float weightAfter  = scaleRead();
    float actualRise   = weightAfter - scaleBaselineGrams;   // positive = weight went up
    float expectedRise = tools[toolIndex].weightGrams;

    Serial.print("[WEIGHT] Return check - baseline: "); Serial.print(scaleBaselineGrams, 1);
    Serial.print("g  after: ");      Serial.print(weightAfter, 1);
    Serial.print("g  rise: ");       Serial.print(actualRise, 1);
    Serial.print("g  expected: ");   Serial.print(expectedRise, 1); Serial.println("g");

    if (weightDeltaMatches(expectedRise, actualRise)) {
      // Weight matches — confirm return
      tools[toolIndex].present = true;
      tools[toolIndex].checkedOutBy = nullptr;
      scaleBaselineGrams = weightAfter;   // update baseline

      Serial.print("RETURN,,"); Serial.println(tools[toolIndex].name);
      BLE_sendReturn(tools[toolIndex].name);

      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Tool Returned:");
      display.println(tools[toolIndex].name);
      display.println("Weight OK");
      display.display();
      delay(1500);
    } else {
      // Weight doesn't match — flag it, don't mark as returned
      Serial.println("[WEIGHT] MISMATCH on return — tool not confirmed.");

      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Return Failed!");
      display.println("Weight mismatch.");
      display.println("Try again.");
      display.display();
      delay(2500);
    }

    showDefaultScreen();
    return;  // early return — card already halted above

  } else {
    // CHECKOUT path
    if (!sessionActive) {
      Serial.println("CHECKOUT_BLOCKED,NO_SESSION");
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Login required!");
      display.println("Swipe card on");
      display.println("login reader.");
      display.display();
      delay(2000);
      showDefaultScreen();
    } else if (!authorizeTag(&rfidTools.uid)) {
      Serial.print("AUTH_FAILED,");
      Serial.println(tools[toolIndex].name);

      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Auth Failed!");
      display.println("Clone/tampered?");
      display.display();
      delay(2000);
      showSessionScreen();
    } else {
      // Authorized checkout — mark tool as out
      tools[toolIndex].present = false;
      tools[toolIndex].checkedOutBy = currentUser->name;

      Serial.print("CHECKOUT,");
      Serial.print(currentUser->name);
      Serial.print(",");
      Serial.println(tools[toolIndex].name);

      BLE_sendCheckout(currentUser->name, tools[toolIndex].name);

      if (!alreadyTouchedThisSession(toolIndex))
        sessionToolsTouched[sessionToolCount++] = toolIndex;

      sessionStartTime = millis();
      showSessionScreen();
    }
  }

  rfidTools.PICC_HaltA();
  rfidTools.PCD_StopCrypto1();
}

// ============================================================
// HANDLE PROVISION READER (GPIO 15)
// Tap any tool tag here to provision it — no BLE/app needed
// ============================================================
void handleProvisionReader() {
  if (!rfidProvision.PICC_IsNewCardPresent()) return;
  if (!rfidProvision.PICC_ReadCardSerial()) return;

  Serial.println("[PROVISION] Tag detected on provision reader.");

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("Provisioning...");
  display.display();

  bool ok = rfidProvisionCurrentToolTag(rfidProvision, 0);

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(ok ? "Provision OK!" : "Provision FAIL");
  if (!ok) display.println("Check serial log");
  display.display();
  delay(1500);

  if (sessionActive) showSessionScreen(); else showDefaultScreen();
}

// ============================================================
// UNAUTHORIZED REMOVAL CHECK
// Called every loop when no session is active.
// If the scale drops significantly without any checkout event,
// it means someone took a tool without scanning.
// ============================================================
#define UNAUTHORIZED_REMOVAL_THRESHOLD_G 50.0f  // minimum drop to trigger alert
                                                 // TODO: tune after calibration

void checkUnauthorizedRemoval() {
  if (sessionActive) return;  // during a session, removals are expected
  if (!scale.is_ready()) return;

  float currentWeight = scaleRead();
  float delta = scaleBaselineGrams - currentWeight;  // positive = weight dropped

  if (delta > UNAUTHORIZED_REMOVAL_THRESHOLD_G) {
    Serial.print("[WEIGHT] UNAUTHORIZED REMOVAL detected! Drop: ");
    Serial.print(delta, 1); Serial.println("g");

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("!! ALERT !!");
    display.println("Unauthorized");
    display.println("removal detected");
    display.print("-"); display.print((int)delta); display.println("g");
    display.display();
    delay(3000);

    BLE_sendUnauthorizedRemoval(delta);

    // Don't update baseline here — we want the alert to keep
    // firing until the tool is returned or a legitimate checkout happens.
    showDefaultScreen();
  }
}

// ============================================================
// HANDLE BLE COMMANDS
// ============================================================
void handleBLECommands() {
  if (!BLE_hasNewMessage()) return;

  String message = BLE_getLastMessage();
  Serial.print("[BLE] Processing command: ");
  Serial.println(message);

  if (!bleLinkEncrypted) {
    Serial.println("[BLE] Ignoring command (not encrypted).");
    return;
  }

  if (message.indexOf("get_inventory") >= 0) {
    BLE_sendFullInventory();
  }

  // BLE provisioning path kept but commented out —
  // provisioning is now handled by the dedicated reader on GPIO 15.
  // Uncomment if you want to re-enable BLE-triggered provisioning.
  //
  // if (message.indexOf("provision_tool_tag") >= 0) {
  //   display.clearDisplay();
  //   display.setCursor(0, 0);
  //   display.println("Provision mode");
  //   display.println("Tap tool fob");
  //   display.display();
  //
  //   unsigned long t0 = millis();
  //   bool ok = false;
  //   while (millis() - t0 < 8000) {
  //     if (rfidProvisionCurrentToolTag(rfidTools, 0)) { ok = true; break; }
  //     delay(100);
  //   }
  //
  //   display.clearDisplay();
  //   display.setCursor(0, 0);
  //   display.println(ok ? "Provision OK" : "Provision FAIL");
  //   display.display();
  //   delay(1500);
  //   if (sessionActive) showSessionScreen(); else showDefaultScreen();
  // }
}

// ============================================================
// SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("=== Smart Toolbox Initializing ===");

  Wire.begin(21, 22);
  Wire.setClock(400000);

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED_FAILED");
  } else {
    Serial.println("OLED_READY");
  }

  BLE_init_secure();

  SPI.begin();
  rfidTools.PCD_Init();    delay(50);
  rfidUsers.PCD_Init();    delay(50);
  rfidProvision.PCD_Init(); delay(50);

  if (!rfidSecurityInitKeys()) {
    Serial.println("[RFID] Security init failed; halting.");
    while (true) delay(1000);
  }

  byte vTools = rfidTools.PCD_ReadRegister(rfidTools.VersionReg);
  byte vUsers = rfidUsers.PCD_ReadRegister(rfidUsers.VersionReg);
  byte vProv  = rfidProvision.PCD_ReadRegister(rfidProvision.VersionReg);

  if (vTools != 0x00 && vTools != 0xFF) {
    Serial.print("READER_TOOLS_READY,0x"); Serial.println(vTools, HEX);
  } else { Serial.println("READER_TOOLS_FAILED"); }

  if (vUsers != 0x00 && vUsers != 0xFF) {
    Serial.print("READER_USERS_READY,0x"); Serial.println(vUsers, HEX);
  } else { Serial.println("READER_USERS_FAILED"); }

  if (vProv != 0x00 && vProv != 0xFF) {
    Serial.print("READER_PROVISION_READY,0x"); Serial.println(vProv, HEX);
  } else { Serial.println("READER_PROVISION_FAILED"); }

  // Initialize load cell
  scale.begin(LOADCELL_DOUT_PIN, LOADCELL_SCK_PIN);
  scale.set_scale(CALIBRATION_FACTOR);

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("Taring scale...");
  display.println("Keep all tools");
  display.println("in the box!");
  display.display();

  // Tare with all tools present — this zeros the scale
  // so all future readings are relative to this point.
  // Make sure all tools are in the box at startup.
  scale.tare();
  scaleBaselineGrams = 0.0f;  // after tare, all-tools-in = 0g delta
  Serial.println("[SCALE] Tare complete. Baseline = 0g (all tools in).");

  showDefaultScreen();
  logAllTools();
  Serial.println("=== Ready ===");
}

// ============================================================
// MAIN LOOP
// ============================================================
void loop() {
  // Auto-logout on inactivity
  if (sessionActive && (millis() - sessionStartTime > SESSION_TIMEOUT_MS)) {
    Serial.println("SESSION_TIMEOUT");
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Session timed out.");
    display.println("Auto-logged out.");
    display.display();
    delay(2000);
    endSession();
  }

  handleUserReader();
  handleToolReader();
  handleProvisionReader();
  checkUnauthorizedRemoval();
  handleBLECommands();
  delay(80);
}
