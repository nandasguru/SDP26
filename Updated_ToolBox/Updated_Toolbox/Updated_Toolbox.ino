#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// ============================================================
// BLE INCLUDES
// ============================================================
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

// ============================================================
// BLE CONFIGURATION
// ============================================================
#define BLE_SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define BLE_CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

BLECharacteristic *pCharacteristic = nullptr;
bool bleDeviceConnected = false;
String bleLastReceivedMessage = "";

// ============================================================
// PIN DEFINITIONS
// ============================================================
#define SS_PIN_TOOLS  4   // Reader for tool tags
#define SS_PIN_USERS  5   // Reader for user cards
#define RST_PIN       17  // Shared RST

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
};

Tool tools[NUM_TOOLS] = {
  { "Tool1", {0x02, 0x1D, 0xB3, 0xAB}, true, nullptr },
  { "Tool2", {0xB2, 0x27, 0x9D, 0xAB}, true, nullptr },
  { "Tool3", {0xC2, 0x66, 0xBB, 0xAB}, true, nullptr }
};

// ============================================================
// SESSION STATE
// ============================================================
bool sessionActive = false;
User* currentUser = nullptr;
int sessionToolsTouched[NUM_TOOLS];
int sessionToolCount = 0;

// ============================================================
// NEW: DEBOUNCE + AUTO-LOGOUT TIMER
// ============================================================
unsigned long lastUserScan = 0;
#define USER_SCAN_DEBOUNCE_MS 1500      // ignore re-taps within 1.5 seconds

unsigned long sessionStartTime = 0;
#define SESSION_TIMEOUT_MS 10000       // auto-logout after 10 seconds of inactivity

// ============================================================
// SECURITY HOOK (for teammate to fill in later)
// ============================================================
bool authorizeTag(MFRC522::Uid* uid) {
  // TODO: teammate plugs in HMAC auth here
  return true;
}

// ============================================================
// BLE CALLBACK CLASSES
// ============================================================

class MyBLEServerCallbacks: public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    bleDeviceConnected = true;
    Serial.println("[BLE] Device connected");
  }

  void onDisconnect(BLEServer* pServer) {
    bleDeviceConnected = false;
    Serial.println("[BLE] Device disconnected");
    pServer->startAdvertising();
    Serial.println("[BLE] Advertising restarted");
  }
};

class MyBLECharacteristicCallbacks: public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    String value = pCharacteristic->getValue().c_str();
    
    if (value.length() > 0) {
      bleLastReceivedMessage = value;
      Serial.print("[BLE] Received: ");
      Serial.println(bleLastReceivedMessage);
    }
  }
};

// ============================================================
// BLE FUNCTIONS
// ============================================================

void BLE_init() {
  Serial.println("[BLE] Initializing...");
  
  BLEDevice::init("SmartToolbox");
  
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
  
  pCharacteristic->setCallbacks(new MyBLECharacteristicCallbacks());
  pCharacteristic->addDescriptor(new BLE2902());
  
  pService->start();
  
  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(BLE_SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);
  pAdvertising->setMinPreferred(0x12);
  BLEDevice::startAdvertising();
  
  Serial.println("[BLE] Ready and advertising as 'SmartToolbox'");
}

bool BLE_isConnected() {
  return bleDeviceConnected;
}

bool BLE_sendMessage(String message) {
  if (!bleDeviceConnected || pCharacteristic == nullptr) {
    return false;
  }
  
  pCharacteristic->setValue(message);
  pCharacteristic->notify();
  Serial.println("[BLE] Sent: " + message);
  return true;
}

bool BLE_hasNewMessage() {
  return (bleLastReceivedMessage.length() > 0);
}

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
  String json = "{\"event\":\"login\",\"user\":\"" + String(userName) + "\"}";
  BLE_sendMessage(json);
}

void BLE_sendLogout(const char* userName) {
  if (!BLE_isConnected()) return;
  String json = "{\"event\":\"logout\",\"user\":\"" + String(userName) + "\"}";
  BLE_sendMessage(json);
}

void BLE_sendCheckout(const char* userName, const char* toolName) {
  if (!BLE_isConnected()) return;
  String json = "{\"event\":\"checkout\",\"user\":\"" + String(userName) + 
                "\",\"tool\":\"" + String(toolName) + "\"}";
  BLE_sendMessage(json);
}

void BLE_sendReturn(const char* toolName) {
  if (!BLE_isConnected()) return;
  String json = "{\"event\":\"return\",\"tool\":\"" + String(toolName) + "\"}";
  BLE_sendMessage(json);
}

// Send full inventory state (all tools and their statuses)
void BLE_sendFullInventory() {
  if (!BLE_isConnected()) return;
  
  String json = "{\"event\":\"inventory\",\"tools\":[";
  
  for (int i = 0; i < NUM_TOOLS; i++) {
    if (i > 0) json += ",";
    json += "{\"name\":\"" + String(tools[i].name) + "\",";
    json += "\"status\":\"" + String(tools[i].present ? "in" : "out") + "\"";
    if (!tools[i].present && tools[i].checkedOutBy != nullptr) {
      json += ",\"user\":\"" + String(tools[i].checkedOutBy) + "\"";
    }
    json += "}";
  }
  
  json += "]}";
  BLE_sendMessage(json);
}

// ============================================================
// HELPERS
// ============================================================
int findToolByUID(MFRC522::Uid* uid) {
  if (uid->size != 4) return -1;
  for (int i = 0; i < NUM_TOOLS; i++) {
    if (memcmp(uid->uidByte, tools[i].uid, 4) == 0) return i;
  }
  return -1;
}

int findUserByUID(MFRC522::Uid* uid) {
  if (uid->size != 4) return -1;
  for (int i = 0; i < NUM_USERS; i++) {
    if (memcmp(uid->uidByte, users[i].uid, 4) == 0) return i;
  }
  return -1;
}

bool alreadyTouchedThisSession(int toolIndex) {
  for (int i = 0; i < sessionToolCount; i++) {
    if (sessionToolsTouched[i] == toolIndex) return true;
  }
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
    for (int i = 0; i < sessionToolCount; i++) {
      display.println(tools[sessionToolsTouched[i]].name);
    }
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
  sessionStartTime = millis();  // start the inactivity timer

  Serial.print("LOGIN,");
  Serial.println(user->name);

  BLE_sendLogin(user->name);

  showSessionScreen();
}

void endSession() {
  Serial.print("LOGOUT,");
  Serial.println(currentUser->name);

  BLE_sendLogout(currentUser->name);

  sessionActive = false;
  currentUser = nullptr;
  sessionToolCount = 0;

  showDefaultScreen();
  logAllTools();
}

// ============================================================
// HANDLE USER READER (Reader 5)
// ============================================================
void handleUserReader() {
  if (!rfidUsers.PICC_IsNewCardPresent()) return;
  if (!rfidUsers.PICC_ReadCardSerial()) return;

  // Debounce: ignore taps that come in too fast after the last one
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
// HANDLE TOOL READER (Reader 4)
// ============================================================
void handleToolReader() {
  if (!rfidTools.PICC_IsNewCardPresent()) return;
  if (!rfidTools.PICC_ReadCardSerial()) return;

  int toolIndex = findToolByUID(&rfidTools.uid);

  if (toolIndex != -1) {
    bool isReturning = !tools[toolIndex].present;

    if (isReturning) {
      // Block returns during active session — do nothing
      if (sessionActive) {
        rfidTools.PICC_HaltA();
        rfidTools.PCD_StopCrypto1();
        return;
      }

      // Anyone can return without login
      tools[toolIndex].present = true;
      tools[toolIndex].checkedOutBy = nullptr;

      Serial.print("RETURN,,");
      Serial.println(tools[toolIndex].name);

      BLE_sendReturn(tools[toolIndex].name);

      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Tool Returned:");
      display.println(tools[toolIndex].name);
      display.display();
      delay(1500);

      showDefaultScreen();

    } else {
      // Checkout requires login
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
      } else {
        if (!authorizeTag(&rfidTools.uid)) {
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
          tools[toolIndex].present = false;
          tools[toolIndex].checkedOutBy = currentUser->name;

          Serial.print("CHECKOUT,");
          Serial.print(currentUser->name);
          Serial.print(",");
          Serial.println(tools[toolIndex].name);

          BLE_sendCheckout(currentUser->name, tools[toolIndex].name);

          if (!alreadyTouchedThisSession(toolIndex)) {
            sessionToolsTouched[sessionToolCount++] = toolIndex;
          }

          // Reset inactivity timer on every tool scan
          sessionStartTime = millis();

          showSessionScreen();
        }
      }
    }
  }

  rfidTools.PICC_HaltA();
  rfidTools.PCD_StopCrypto1();
}

// ============================================================
// HANDLE BLE COMMANDS FROM APP
// ============================================================
void handleBLECommands() {
  if (!BLE_hasNewMessage()) return;
  
  String message = BLE_getLastMessage();
  Serial.print("[BLE] Processing command: ");
  Serial.println(message);
  
  // App requesting full inventory refresh
  if (message.indexOf("get_inventory") >= 0) {
    BLE_sendFullInventory();
  }
}

// ============================================================
// SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println("=== Smart Toolbox Initializing ===");

  BLE_init();

  Wire.begin(21, 22);
  Wire.setClock(400000);

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED_FAILED");
  } else {
    Serial.println("OLED_READY");
  }

  SPI.begin();

  rfidTools.PCD_Init();
  delay(50);
  rfidUsers.PCD_Init();
  delay(50);

  byte vTools = rfidTools.PCD_ReadRegister(rfidTools.VersionReg);
  byte vUsers = rfidUsers.PCD_ReadRegister(rfidUsers.VersionReg);

  if (vTools != 0x00 && vTools != 0xFF) {
    Serial.print("READER_TOOLS_READY,0x");
    Serial.println(vTools, HEX);
  } else {
    Serial.println("READER_TOOLS_FAILED");
  }

  if (vUsers != 0x00 && vUsers != 0xFF) {
    Serial.print("READER_USERS_READY,0x");
    Serial.println(vUsers, HEX);
  } else {
    Serial.println("READER_USERS_FAILED");
  }

  showDefaultScreen();
  logAllTools();

  Serial.println("=== Ready ===");
}

// ============================================================
// MAIN LOOP
// ============================================================
void loop() {
  // Auto-logout on inactivity timeout — checkouts are kept as-is
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
  handleBLECommands();
  delay(100);
}
