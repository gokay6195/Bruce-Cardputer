#ifndef LITE_VERSION
#include "emv_reader.hpp"
#include <vector>

void EMVReader::setup() {
    returnToMenu = true;
}

void EMVReader::display_emv(EMVCard card) {}
void EMVReader::save_emv(const char* p, const char* f, const char* t, const char* a) {}
void EMVReader::parse_pan(std::vector<uint8_t> *a, EMVCard *c) {}
void EMVReader::parse_validfrom(std::vector<uint8_t> *a, EMVCard *c) {}
void EMVReader::parse_validto(std::vector<uint8_t> *a, EMVCard *c) {}

#endif
