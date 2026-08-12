/**
 * @file RFID2.h
 * @author Rennan Cockles (https://github.com/rennancockles)
 * @brief Read and Write RFID tags using RFID2 module from M5Stack
 * @version 0.2 - Improved by community
 * @date 2024-08-19
 */

#include "RFIDInterface.h"
#include <MFRC522Driver.h>
#include <MFRC522DriverPinSimple.h>
#include <MFRC522v2.h>

// Nouveau code retour : lecture partielle (certains secteurs verrouillés)
#define PARTIAL_SUCCESS 5

class RFID2 : public RFIDInterface {
public:
    MFRC522 mfrc522;

    /////////////////////////////////////////////////////////////////////////////////////
    // Constructor
    /////////////////////////////////////////////////////////////////////////////////////
    RFID2(bool use_i2c = true);
    ~RFID2();

    /////////////////////////////////////////////////////////////////////////////////////
    // Life Cycle
    /////////////////////////////////////////////////////////////////////////////////////
    bool begin();

    /////////////////////////////////////////////////////////////////////////////////////
    // Operations
    /////////////////////////////////////////////////////////////////////////////////////
    int read(int cardBaudRate = 0);
    int clone();
    int erase();
    int write(int cardBaudRate = 0);
    int write_ndef();
    int load();
    int save(String filename);

private:
    bool _use_i2c;
    MFRC522Driver *_driver;
    MFRC522DriverPinSimple ss_pin = MFRC522DriverPinSimple(SPI_SS_PIN);

    /////////////////////////////////////////////////////////////////////////////////////
    // Converters
    /////////////////////////////////////////////////////////////////////////////////////
    void format_data();
    void parse_data();
    void set_uid();

    /////////////////////////////////////////////////////////////////////////////////////
    // PICC Helpers
    /////////////////////////////////////////////////////////////////////////////////////
    bool PICC_IsNewCardPresent();

    String get_tag_type();
    int read_data_blocks();
    int read_mifare_classic_data_blocks(byte piccType);
    int read_mifare_classic_data_sector(byte sector);
    int authenticate_mifare_classic(byte block);
    int read_mifare_ultralight_data_blocks();

    int write_data_blocks();
    // Signature mise à jour : do_auth=false permet d'éviter de ré-authentifier
    // à chaque bloc quand on écrit plusieurs blocs d'un même secteur
    bool write_mifare_classic_data_block(int block, String data, bool do_auth = true);
    bool write_mifare_ultralight_data_block(int block, String data);

    int erase_data_blocks();
    int write_ndef_blocks();
};
