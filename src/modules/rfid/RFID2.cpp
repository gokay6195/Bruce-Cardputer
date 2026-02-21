/**
 * @file RFID2.cpp
 * @author Rennan Cockles (https://github.com/rennancockles)
 * @brief Read and Write RFID tags using RFID2 module from M5Stack
 * @version 0.1
 * @date 2024-08-19
 */

#include "RFID2.h"
#include "core/display.h"
#include "core/i2c_finder.h"
#include "core/sd_functions.h"
#include <MFRC522DriverI2C.h>
#include <MFRC522DriverSPI.h>
#include <MFRC522Hack.h>

#define RFID2_I2C_ADDRESS 0x28

RFID2::RFID2(bool use_i2c) : _use_i2c(use_i2c) {
    if (use_i2c)
        _driver =
            new MFRC522DriverI2C{RFID2_I2C_ADDRESS, bruceConfigPins.i2c_bus.sda, bruceConfigPins.i2c_bus.scl};
    else _driver = new MFRC522DriverSPI{ss_pin, SPI_SCK_PIN, SPI_MISO_PIN, SPI_MOSI_PIN};
    mfrc522.SetDriver(*_driver);
}

RFID2::~RFID2() { delete _driver; }

bool RFID2::begin() {
    bool i2c_check = check_i2c_address(RFID2_I2C_ADDRESS);

    mfrc522.PCD_Init();
    mfrc522.PCD_SetAntennaGain(0x07 << 4);

    MFRC522::PCD_Version version = mfrc522.PCD_GetVersion();

    return i2c_check || version != MFRC522::PCD_Version::Version_Unknown;
}

bool RFID2::PICC_IsNewCardPresent() {
    byte bufferATQA[2];
    byte bufferSize = sizeof(bufferATQA);
    byte result = mfrc522.PICC_RequestA(bufferATQA, &bufferSize);
    bool bl_result =
        (result == MFRC522::StatusCode::STATUS_OK || result == MFRC522::StatusCode::STATUS_COLLISION);
    if (bl_result) {
        printableUID.atqa = "";
        for (byte i = 0; i < bufferSize; i++) {
            printableUID.atqa += bufferATQA[i] < 0x10 ? " 0" : " ";
            printableUID.atqa += String(bufferATQA[i], HEX);
        }
        printableUID.atqa.trim();
        printableUID.atqa.toUpperCase();
    }
    return bl_result;
}

int RFID2::read(int cardBaudRate) {
    pageReadStatus = FAILURE;

    if (!PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) return TAG_NOT_PRESENT;

    displayInfo("Reading data blocks...");
    pageReadStatus = read_data_blocks();
    pageReadSuccess = pageReadStatus == SUCCESS;
    format_data();
    set_uid();
    return SUCCESS;
}

int RFID2::clone() {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) { return TAG_NOT_PRESENT; }

    if (mfrc522.uid.sak != uid.sak) return TAG_NOT_MATCH;

    MFRC522Hack mfrc522Hack(mfrc522, true);
    MFRC522::MIFARE_Key key = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    bool success = mfrc522Hack.MIFARE_SetUid(uid.uidByte, uid.size, key, true);
    mfrc522.PICC_HaltA();
    return success ? SUCCESS : FAILURE;
}

int RFID2::erase() {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) { return TAG_NOT_PRESENT; }

    int result = erase_data_blocks();
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    return result;
}

int RFID2::write(int cardBaudRate) {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) { return TAG_NOT_PRESENT; }

    if (mfrc522.uid.sak != uid.sak) return TAG_NOT_MATCH;

    int result = write_data_blocks();

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    return result;
}

int RFID2::write_ndef() {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) { return TAG_NOT_PRESENT; }

    int result = write_ndef_blocks();

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    return result;
}

int RFID2::load() {
    String filepath;
    File file;
    FS *fs;

    if (!getFsStorage(fs)) return FAILURE;
    filepath = loopSD(*fs, true, "RFID|NFC", "/BruceRFID");
    file = fs->open(filepath, FILE_READ);

    if (!file) { return FAILURE; }

    String line;
    String strData;
    strAllPages = "";
    pageReadSuccess = true;

    while (file.available()) {
        line = file.readStringUntil('\n');
        strData = line.substring(line.indexOf(":") + 1);
        strData.trim();
        if (line.startsWith("Device type:")) printableUID.picc_type = strData;
        if (line.startsWith("UID:")) printableUID.uid = strData;
        if (line.startsWith("SAK:")) printableUID.sak = strData;
        if (line.startsWith("ATQA:")) printableUID.atqa = strData;
        if (line.startsWith("Pages total:")) dataPages = strData.toInt();
        if (line.startsWith("Pages read:")) pageReadSuccess = false;
        if (line.startsWith("Page ")) strAllPages += line + "\n";
    }

    file.close();
    delay(100);
    parse_data();

    return SUCCESS;
}

int RFID2::save(String filename) {
    FS *fs;
    if (!getFsStorage(fs)) return FAILURE;

    if (!(*fs).exists("/BruceRFID")) (*fs).mkdir("/BruceRFID");
    if ((*fs).exists("/BruceRFID/" + filename + ".rfid")) {
        int i = 1;
        filename += "_";
        while ((*fs).exists("/BruceRFID/" + filename + String(i) + ".rfid")) i++;
        filename += String(i);
    }
    File file = (*fs).open("/BruceRFID/" + filename + ".rfid", FILE_WRITE);

    if (!file) { return FAILURE; }

    file.println("Filetype: Bruce RFID File");
    file.println("Version 1");
    file.println("Device type: " + printableUID.picc_type);
    file.println("# UID, ATQA and SAK are common for all formats");
    file.println("UID: " + printableUID.uid);
    file.println("SAK: " + printableUID.sak);
    file.println("ATQA: " + printableUID.atqa);
    file.println("# Memory dump");
    file.println("Pages total: " + String(dataPages));
    if (!pageReadSuccess) file.println("Pages read: " + String(dataPages));
    file.print(strAllPages);

    file.close();
    delay(100);
    return SUCCESS;
}

String RFID2::get_tag_type() {
    byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    String tag_type = mfrc522.PICC_GetTypeName(piccType);

    if (piccType == MFRC522::PICC_Type::PICC_TYPE_MIFARE_UL) {
        switch (totalPages) {
            case 45: tag_type = "NTAG213"; break;
            case 135: tag_type = "NTAG215"; break;
            case 231: tag_type = "NTAG216"; break;
            default: break;
        }
    }

    return tag_type;
}

void RFID2::set_uid() {
    uid.sak = mfrc522.uid.sak;
    uid.size = mfrc522.uid.size;

    for (byte i = 0; i < mfrc522.uid.size; i++) { uid.uidByte[i] = mfrc522.uid.uidByte[i]; }
}

void RFID2::format_data() {
    byte bcc = 0;

    printableUID.picc_type = get_tag_type();

    printableUID.sak = mfrc522.uid.sak < 0x10 ? "0" : "";
    printableUID.sak += String(mfrc522.uid.sak, HEX);
    printableUID.sak.toUpperCase();

    // UID
    printableUID.uid = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
        printableUID.uid += mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ";
        printableUID.uid += String(mfrc522.uid.uidByte[i], HEX);
        bcc = bcc ^ mfrc522.uid.uidByte[i];
    }
    printableUID.uid.trim();
    printableUID.uid.toUpperCase();

    // BCC
    printableUID.bcc = bcc < 0x10 ? "0" : "";
    printableUID.bcc += String(bcc, HEX);
    printableUID.bcc.toUpperCase();

    // ATQA
    String atqaPart1 = printableUID.atqa.substring(0, 2);
    String atqaPart2 = printableUID.atqa.substring(3, 5);
    printableUID.atqa = atqaPart2 + " " + atqaPart1;
}

void RFID2::parse_data() {
    String strUID = printableUID.uid;
    strUID.trim();
    strUID.replace(" ", "");
    uid.size = strUID.length() / 2;
    for (size_t i = 0; i < strUID.length(); i += 2) {
        uid.uidByte[i / 2] = strtoul(strUID.substring(i, i + 2).c_str(), NULL, 16);
    }

    printableUID.sak.trim();
    uid.sak = strtoul(printableUID.sak.c_str(), NULL, 16);
}

int RFID2::read_data_blocks() {
    dataPages = 0;
    totalPages = 0;
    int readStatus = FAILURE;
    byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    strAllPages = "";

    switch (piccType) {
        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_MINI:
        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_1K:
        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_4K:
            readStatus = read_mifare_classic_data_blocks(piccType);
            break;

        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_UL:
            readStatus = read_mifare_ultralight_data_blocks();
            dataPages = (readStatus == SUCCESS && dataPages > 0) ? dataPages - 1 : dataPages;
            if (totalPages == 0) totalPages = dataPages;
            break;

        default: break;
    }

    mfrc522.PICC_HaltA();
    return readStatus;
}

int RFID2::read_mifare_classic_data_blocks(byte piccType) {
    byte no_of_sectors = 0;
    int sectorReadStatus = FAILURE;

    switch (piccType) {
        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_MINI:
            no_of_sectors = 5;
            totalPages = 20; // 320 bytes / 16 bytes per page
            break;

        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_1K:
            no_of_sectors = 16;
            totalPages = 64; // 1024 bytes / 16 bytes per page
            break;

        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_4K:
            no_of_sectors = 40;
            totalPages = 256; // 4096 bytes / 16 bytes per page
            break;

        default: // Should not happen. Ignore.
            break;
    }

    if (no_of_sectors) {
        for (int8_t i = 0; i < no_of_sectors; i++) {
            sectorReadStatus = read_mifare_classic_data_sector(i);
            if (sectorReadStatus != SUCCESS) break;
        }
    }
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    return sectorReadStatus;
}

int RFID2::read_mifare_classic_data_sector(byte sector) {
    byte status;
    byte firstBlock;
    byte no_of_blocks;

    if (sector < 32) {
        no_of_blocks = 4;
        firstBlock = sector * no_of_blocks;
    } else if (sector < 40) {
        no_of_blocks = 16;
        firstBlock = 128 + (sector - 32) * no_of_blocks;
    } else {
        return FAILURE;
    }

    byte byteCount;
    byte buffer[18];
    byte blockAddr;
    String strPage;

    int authStatus = authenticate_mifare_classic(firstBlock);
    // if (authStatus != SUCCESS) return authStatus; 

    for (int8_t blockOffset = 0; blockOffset < no_of_blocks; blockOffset++) {
        strPage = "";
        blockAddr = firstBlock + blockOffset;
        byteCount = sizeof(buffer);

        status = mfrc522.MIFARE_Read(blockAddr, buffer, &byteCount);
        if (status != MFRC522::StatusCode::STATUS_OK) { return FAILURE; }

        for (byte index = 0; index < 16; index++) {
            strPage += buffer[index] < 0x10 ? F(" 0") : F(" ");
            strPage += String(buffer[index], HEX);
        }

        strPage.trim();
        strPage.toUpperCase();

        strAllPages += "Page " + String(dataPages) + ": " + strPage + "\n";
        dataPages++;
    }

    return SUCCESS;
}

int RFID2::authenticate_mifare_classic(byte block) {
    uint8_t dict_keys[80][6] = {
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5}, {0xB0,0xB1,0xB2,0xB3,0xB4,0xB5},
        {0x4D,0x3A,0x99,0xC3,0x51,0xDD}, {0x1A,0x98,0x2C,0x7E,0x45,0x9A}, {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},
        {0x71,0x4C,0x5C,0x88,0x6E,0x97}, {0x58,0x7E,0xE5,0xF9,0x35,0x0F}, {0xA0,0x47,0x8C,0xC3,0x90,0x91},
        {0x53,0x3C,0xB6,0xC7,0x23,0xF6}, {0x8F,0xD0,0xA4,0xF2,0x56,0xE9}, {0xA6,0x45,0x98,0xA7,0x74,0x78},
        {0x26,0x94,0x0B,0x21,0xFF,0x5D}, {0xFC,0x00,0x01,0x87,0x78,0xF7}, {0x00,0x00,0x0F,0xFE,0x24,0x88},
        {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7}, {0xA0,0xB0,0xC0,0xD0,0xE0,0xF0}, {0xA1,0xB1,0xC1,0xD1,0xE1,0xF1},
        {0x12,0x34,0x56,0x78,0x9A,0xBC}, {0x01,0x02,0x03,0x04,0x05,0x06}, {0x11,0x22,0x33,0x44,0x55,0x66},
        {0x99,0x99,0x99,0x99,0x99,0x99}, {0x77,0x77,0x77,0x77,0x77,0x77}, {0xE1,0x10,0xDC,0x2F,0x10,0xDC},
        {0x32,0xA1,0x85,0x33,0x22,0x11}, {0x44,0x44,0x44,0x44,0x44,0x44}, {0x88,0x88,0x88,0x88,0x88,0x88},
        {0x04,0x19,0x2B,0x27,0x0B,0x09}, {0x19,0x70,0x03,0x03,0x19,0x70}, {0x10,0x10,0x10,0x10,0x10,0x10},
        {0x01,0x23,0x45,0x67,0x89,0xAB}, {0x41,0x43,0x52,0x31,0x32,0x32}, {0x13,0x57,0x9A,0xDF,0x26,0x48},
        {0xFF,0x00,0xFF,0x00,0xFF,0x00}, {0x00,0x00,0x00,0x00,0x00,0x00}, {0x14,0x07,0x88,0x14,0x07,0x88},
        {0x20,0x21,0x22,0x23,0x24,0x25}, {0x60,0x61,0x62,0x63,0x64,0x65}, {0x70,0x71,0x72,0x73,0x74,0x75},
        {0x80,0x81,0x82,0x83,0x84,0x85}, {0x90,0x91,0x92,0x93,0x94,0x95}, {0xA0,0xB1,0xC2,0xD3,0xE4,0xF5},
        {0x54,0x43,0x52,0x11,0x22,0x33}, {0x08,0x08,0x08,0x08,0x08,0x08}, {0x4B,0x45,0x59,0x47,0x45,0x4E},
        {0xAB,0xCD,0xEF,0x12,0x34,0x56}, {0x25,0x82,0xA1,0x99,0x77,0x00}, {0x12,0x12,0x12,0x12,0x12,0x12},
        {0x34,0x34,0x34,0x34,0x34,0x34}, {0x56,0x56,0x56,0x56,0x56,0x56}, {0x78,0x78,0x78,0x78,0x78,0x78},
        {0x90,0x90,0x90,0x90,0x90,0x90}, {0x22,0x22,0x22,0x22,0x22,0x22}, {0x33,0x33,0x33,0x33,0x33,0x33},
        {0x44,0x44,0x44,0x44,0x44,0x44}, {0x55,0x55,0x55,0x55,0x55,0x55}, {0x66,0x66,0x66,0x66,0x66,0x66},
        {0xCC,0xCC,0xCC,0xCC,0xCC,0xCC}, {0xEE,0xEE,0xEE,0xEE,0xEE,0xEE}, {0x11,0x11,0x11,0x11,0x11,0x11},
        {0x22,0x33,0x44,0x55,0x66,0x77}, {0x44,0x55,0x66,0x77,0x88,0x99}, {0x01,0x02,0x03,0x04,0x05,0x01},
        {0xA1,0xA2,0xA3,0xA4,0xA5,0xA6}, {0xB1,0xB2,0xB3,0xB4,0xB5,0xB6}, {0xC1,0xC2,0xC3,0xC4,0xC5,0xC6},
        {0xD1,0xD2,0xD3,0xD4,0xD5,0xD6}, {0x10,0x20,0x30,0x40,0x50,0x60}, {0x07,0x07,0x07,0x07,0x07,0x07},
        {0x09,0x09,0x09,0x09,0x09,0x09}, {0x1A,0x2B,0x3C,0x4D,0x5E,0x6F}, {0x6F,0x5E,0x4D,0x3C,0x2B,0x1A},
        {0xAA,0x55,0xAA,0x55,0xAA,0x55}, {0x55,0xAA,0x55,0xAA,0x55,0xAA}, {0x11,0x11,0x22,0x22,0x33,0x33},
        {0x33,0x33,0x22,0x22,0x11,0x11}, {0x4D,0x49,0x46,0x41,0x52,0x45}, {0x41,0x42,0x43,0x44,0x45,0x46}
    };

    byte sector = block / 4;
    byte trailerBlock = sector * 4 + 3;
    MFRC522::StatusCode status;

    // C'est ICI qu'on change le 50 par 80
    for (int i = 0; i < 80; i++) { 
        delay(100); 
        MFRC522::MIFARE_Key key;
        for (int k = 0; k < 6; k++) { key.keyByte[k] = dict_keys[i][k]; }

        status = mfrc522.PCD_Authenticate(MFRC522::PICC_Command::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
        if (status == MFRC522::StatusCode::STATUS_OK) return SUCCESS;

        status = mfrc522.PCD_Authenticate(MFRC522::PICC_Command::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
        if (status == MFRC522::StatusCode::STATUS_OK) return SUCCESS;
    }
    return TAG_AUTH_ERROR;
}

int RFID2::read_mifare_ultralight_data_blocks() {
    byte status;
    byte byteCount;
    byte buffer[18];
    byte i;
    byte cc;
    String strPage = "";

    for (byte page = 0; page <= 252; page += 4) {
        byteCount = sizeof(buffer);
        status = mfrc522.MIFARE_Read(page, buffer, &byteCount);
        if (status != MFRC522::StatusCode::STATUS_OK) {
            return status == MFRC522::StatusCode::STATUS_MIFARE_NACK ? SUCCESS : FAILURE;
        }
        for (byte offset = 0; offset < 4; offset++) {
            strPage = "";
            if (page + offset == 3) {
                cc = buffer[4 * offset + 2];
                switch (cc) {
                    // NTAG213
                    case 0x12: totalPages = 45; break;
                    // NTAG215
                    case 0x3E: totalPages = 135; break;
                    // NTAG216
                    case 0x6D: totalPages = 231; break;
                    default: break;
                }
            }
            for (byte index = 0; index < 4; index++) {
                i = 4 * offset + index;
                strPage += buffer[i] < 0x10 ? F(" 0") : F(" ");
                strPage += String(buffer[i], HEX);
            }
            strPage.trim();
            strPage.toUpperCase();

            strAllPages += "Page " + String(dataPages) + ": " + strPage + "\n";
            dataPages++;
        }
    }

    return SUCCESS;
}

int RFID2::write_data_blocks() {
    byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    String pageLine = "";
    String strBytes = "";
    int lineBreakIndex;
    int pageIndex;
    bool blockWriteSuccess;
    int totalSize = strAllPages.length();

    while (strAllPages.length() > 0) {
        lineBreakIndex = strAllPages.indexOf("\n");
        pageLine = strAllPages.substring(0, lineBreakIndex);
        strAllPages = strAllPages.substring(lineBreakIndex + 1);

        pageIndex = pageLine.substring(5, pageLine.indexOf(":")).toInt();
        strBytes = pageLine.substring(pageLine.indexOf(":") + 1);
        strBytes.trim();

        if (pageIndex == 0) continue;

        switch (piccType) {
            case MFRC522::PICC_Type::PICC_TYPE_MIFARE_MINI:
            case MFRC522::PICC_Type::PICC_TYPE_MIFARE_1K:
            case MFRC522::PICC_Type::PICC_TYPE_MIFARE_4K:
                if (pageIndex == 0 || (pageIndex + 1) % 4 == 0) continue; // Data blocks for MIFARE Classic
                blockWriteSuccess = write_mifare_classic_data_block(pageIndex, strBytes);
                break;

            case MFRC522::PICC_Type::PICC_TYPE_MIFARE_UL:
                if (pageIndex < 4 || pageIndex >= dataPages - 5) continue; // Data blocks for NTAG21X
                blockWriteSuccess = write_mifare_ultralight_data_block(pageIndex, strBytes);
                break;

            default: blockWriteSuccess = false; break;
        }

        if (!blockWriteSuccess) return FAILURE;

        progressHandler(totalSize - strAllPages.length(), totalSize, "Writing data blocks...");
    }

    return SUCCESS;
}

bool RFID2::write_mifare_classic_data_block(int block, String data) {
    data.replace(" ", "");
    byte size = data.length() / 2;
    byte buffer[size];

    for (size_t i = 0; i < data.length(); i += 2) {
        buffer[i / 2] = strtoul(data.substring(i, i + 2).c_str(), NULL, 16);
    }

    if (authenticate_mifare_classic(block) != SUCCESS) return false;

    byte status = mfrc522.MIFARE_Write((byte)block, buffer, size);
    if (status != MFRC522::StatusCode::STATUS_OK) return false;

    return true;
}

bool RFID2::write_mifare_ultralight_data_block(int block, String data) {
    data.replace(" ", "");
    byte size = data.length() / 2;
    byte buffer[size];

    for (size_t i = 0; i < data.length(); i += 2) {
        buffer[i / 2] = strtoul(data.substring(i, i + 2).c_str(), NULL, 16);
    }

    byte status = mfrc522.MIFARE_Ultralight_Write((byte)block, buffer, size);
    if (status != MFRC522::StatusCode::STATUS_OK) return false;

    return true;
}

int RFID2::erase_data_blocks() {
    byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    bool blockWriteSuccess;

    switch (piccType) {
        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_MINI:
        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_1K:
        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_4K:
            for (byte i = 1; i < 64; i++) {
                if ((i + 1) % 4 == 0) continue;
                blockWriteSuccess =
                    write_mifare_classic_data_block(i, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
                if (!blockWriteSuccess) return FAILURE;
            }
            break;

        case MFRC522::PICC_Type::PICC_TYPE_MIFARE_UL:
            // NDEF stardard
            blockWriteSuccess = write_mifare_ultralight_data_block(4, "03 00 FE 00");
            if (!blockWriteSuccess) return FAILURE;

            for (byte i = 5; i < 130; i++) {
                blockWriteSuccess = write_mifare_ultralight_data_block(i, "00 00 00 00");
                if (!blockWriteSuccess) return FAILURE;
            }
            break;

        default: break;
    }

    return SUCCESS;
}

int RFID2::write_ndef_blocks() {
    byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    if (piccType != MFRC522::PICC_Type::PICC_TYPE_MIFARE_UL) return TAG_NOT_MATCH;

    byte ndef_size = ndefMessage.messageSize + 3;
    byte payload_size = ndef_size % 4 == 0 ? ndef_size : ndef_size + (4 - (ndef_size % 4));
    byte ndef_payload[payload_size];
    byte i;
    bool blockWriteSuccess;

    ndef_payload[0] = ndefMessage.begin;
    ndef_payload[1] = ndefMessage.messageSize;
    ndef_payload[2] = ndefMessage.header;
    ndef_payload[3] = ndefMessage.tnf;
    ndef_payload[4] = ndefMessage.payloadSize;
    ndef_payload[5] = ndefMessage.payloadType;

    for (i = 0; i < ndefMessage.payloadSize; i++) { ndef_payload[i + 6] = ndefMessage.payload[i]; }

    ndef_payload[ndef_size - 1] = ndefMessage.end;

    if (payload_size > ndef_size) {
        for (i = ndef_size; i < payload_size; i++) { ndef_payload[i] = 0; }
    }

    for (int i = 0; i < payload_size; i += 4) {
        int block = 4 + (i / 4);
        byte status = mfrc522.MIFARE_Ultralight_Write((byte)block, ndef_payload + i, 4);
        if (status != MFRC522::StatusCode::STATUS_OK) return FAILURE;
    }

    return SUCCESS;
}
