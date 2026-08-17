/**
 * @file RFID2.h
 * @author Rennan Cockles (https://github.com/rennancockles)
 * @brief Read and Write RFID tags using RFID2 module from M5Stack
 * @version 0.1
 * @date 2024-08-19
 */
#include <Arduino.h>
#include <algorithm>
#include "RFIDInterface.h"
#include <MFRC522Driver.h>
#include <MFRC522DriverPinSimple.h>
#include <MFRC522v2.h>

class RFID2 : public RFIDInterface {
public:
    MFRC522 mfrc522;
    RFID2(bool use_i2c = true);
    ~RFID2();
    bool begin();
    int read(int cardBaudRate = 0);
    int clone();
    int erase();
    int write(int cardBaudRate = 0);
    int write_ndef();
    int load();
    int save(String filename);

private:
    bool _use_i2c;
    int _lastSuccessfulKeyIndex = -1;
    byte _lastSuccessfulSector = 0xFF;
    bool _lastUsedKeyA = true;
    void resetAuthCache();
    MFRC522Driver *_driver;
    MFRC522DriverPinSimple ss_pin = MFRC522DriverPinSimple(SPI_SS_PIN);
    void format_data();
    void parse_data();
    void set_uid();
    bool PICC_IsNewCardPresent();
    String get_tag_type();
    int read_data_blocks();
    int read_mifare_classic_data_blocks(byte piccType);
    int read_mifare_classic_data_sector(byte sector);
    int authenticate_mifare_classic(byte block);
    int read_mifare_ultralight_data_blocks();
    int write_data_blocks();
    bool write_mifare_classic_data_block(int block, String data);
    bool write_mifare_ultralight_data_block(int block, String data);
    int erase_data_blocks();
    int write_ndef_blocks();
};
