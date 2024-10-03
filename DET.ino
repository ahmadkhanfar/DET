/* CODED BY AHMAD K. KHANFAR, 

THE CODE WILL GENERATE DET 128 bit */


#include <Ed25519.h>
#include <RNG.h>
#include <vector>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <bitset>
#include <iostream>
#include <KeccakP-1600-SnP.h>
#include "KeccakP-1600-inplace32BI.c"
using namespace std;
unsigned long lastTransmissionTime = 0;  // To manage timed transmissions
const unsigned long transmissionInterval = 5000;  // 5 seconds
// Function to convert an unsigned int to a binary string with leading zeros
std::string toBinary(unsigned int value, int bits) {
    return std::bitset<64>(value).to_string().substr(64 - bits, bits);  // Convert and trim to required bits
}
// Key variables for private and public key
uint8_t privateKey[32];
uint8_t publicKey[32];
uint8_t contextID[] = { 0x00B5, 0xA69C, 0x795D, 0xF5D5, 0xF008, 0x7F56, 0x843F, 0x2C40 };  // Context ID for DET
//STRUCTS 
struct ORCHID_HASH {
uint8_t hi[32];  
unsigned long long hashOutput: 64; // 64-bit Hash Output (from cryptographic function)
};
struct DET{
  unsigned int prefix: 28;
  unsigned int raa = 14;
  unsigned int hda = 14;
  unsigned int suiteID: 8;
  ORCHID_HASH hash; 
};

DET det;
// Function to perform the cSHAKE128 hash (Keccak P-1600) for ORCHID
void cshake128(const uint8_t *input, size_t inputLen, const uint8_t *customization, size_t customLen, uint8_t *output, size_t outputLen) {
    KeccakP1600_state keccakState;  // Keccak state structure

    // Initialize the Keccak state
    KeccakP1600_StaticInitialize();
    KeccakP1600_Initialize(&keccakState);

    // Absorb customization string and input data
    KeccakP1600_AddBytes(&keccakState, customization, 0, customLen);
    KeccakP1600_AddBytes(&keccakState, input, 0, inputLen);

    // Apply the permutation
    KeccakP1600_Permute_24rounds(&keccakState);

    // Extract the output (only need 8 bytes for the 64-bit hash)
    KeccakP1600_ExtractBytes(&keccakState, output, 0, outputLen);
}

std:: string det_orchid( unsigned int hda,  unsigned int raa,  unsigned int ipv6, unsigned int suitid){
  std::string b_prefix = toBinary(ipv6, 28);
    std::string b_hid = toBinary(raa, 14) + toBinary(hda, 14);
   std::string b_suitid = toBinary(suitid, 8);

// Concatenate b_prefix, b_hid, and b_ogaid to form the ORCHID left side
    std::string h_orchid_left_bin = b_prefix + b_hid + b_suitid;

  String(toBinary(det.prefix, 28).c_str());
 // Convert the binary string to bytes (as required by cSHAKE)
    std::vector<uint8_t> h_orchid_left;
    for (size_t i = 0; i < h_orchid_left_bin.length(); i += 8) {
        std::bitset<8> byte(h_orchid_left_bin.substr(i, 8));
        h_orchid_left.push_back(byte.to_ulong());
}


 // Append the HI (public key) to the input for the hash
  h_orchid_left.insert(h_orchid_left.end(), publicKey, publicKey + 32); 

  // Perform cSHAKE128 hashing (8-byte hash)
    uint8_t h_hash[8];
    cshake128(h_orchid_left.data(), h_orchid_left.size(), contextID, sizeof(contextID), h_hash, sizeof(h_hash));

    // Convert h_hash to a hexadecimal string
    std::string h_hash_str;
    for (int i = 0; i < sizeof(h_hash); i++) {
        char buf[3];
        sprintf(buf, "%02x", h_hash[i]);
        h_hash_str += buf;
    }

    // Combine the binary ORCHID left side and the hashed right side
    std::string h_orchid = h_orchid_left_bin + h_hash_str;

    // Format the ORCHID into an IPv6 address-like string
    std::string formatted_orchid;
    for (size_t i = 0; i < h_orchid.length(); i += 4) {
        formatted_orchid += h_orchid.substr(i, 4) + ":";
    }
    formatted_orchid.pop_back();  // Remove the trailing ':'

    //String test = binaryToHex(h_orchid);

    

    Serial.println("DET ORCHID: " + String(formatted_orchid.c_str()));
    // Serial.println(h_orchid);
    // Serial.println(test);
    return h_orchid;

}






void generateKeys(){
  Ed25519::generatePrivateKey(privateKey);
   Ed25519::derivePublicKey(publicKey, privateKey);
  //memcpy(hi.value, publicKey, 32);

}









void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  generateKeys();
    // Setup the constat values. :
    det.prefix = 0x2001003; 
    det.raa = 16376; 
    det.hda = 1025;
    det.suiteID = 5; 
  
  
}

void loop() {

 
  unsigned long currentTime = millis();
    if (currentTime - lastTransmissionTime >= transmissionInterval) {
        lastTransmissionTime = currentTime;
  // Convert std::string to Arduino String and print it
        Serial.println(String(toBinary(det.prefix, 28).c_str()));  // 28 bits for IPv6 Prefix
        Serial.println(String(toBinary(det.raa, 14).c_str()));  // 14 bits for RAA
        Serial.println(String(toBinary(det.hda, 14).c_str()));  // 14 bits for HDA
        Serial.println(String(toBinary(det.suiteID, 8).c_str()));  // 8 bits SUITID

        for (int i = 0; i< sizeof(privateKey); i++ ){
            Serial.print(privateKey[i]);
        }
          Serial.println();
           for (int i = 0; i< sizeof(publicKey); i++ ){
            Serial.print(publicKey[i]);
        }
   
        det_orchid (det.hda, det.raa, det.prefix, det.suiteID);



    }




}




