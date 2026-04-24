#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

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
// SECURITY HOOK (for teammate to fill in later)
// ============================================================
bool authorizeTag(MFRC522::Uid* uid) {
  // TODO: teammate plugs in HMAC auth here
  return true;
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

  Serial.print("LOGIN,");
  Serial.println(user->name);

  showSessionScreen();
}

void endSession() {
  Serial.print("LOGOUT,");
  Serial.println(currentUser->name);

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

          if (!alreadyTouchedThisSession(toolIndex)) {
            sessionToolsTouched[sessionToolCount++] = toolIndex;
          }
          showSessionScreen();
        }
      }
    }
  }

  rfidTools.PICC_HaltA();
  rfidTools.PCD_StopCrypto1();
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
  handleUserReader();
  handleToolReader();
  delay(100);
}