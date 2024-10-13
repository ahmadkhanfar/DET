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
#include <WiFi.h>
#include <time.h>  // For Unix timestamps

using namespace std;

// Wi-Fi Credentials
const char* ssid = "Khanfar";
const char* password = "khalid123";


// NTP Server Settings
const char* ntpServer = "pool.ntp.org";
const long gmtOffset_sec = 0;  // Adjust if you need a specific time zone offset
const int daylightOffset_sec = 0;


// Defining Parent DET as custom for now 
// DET (16 bytes) stored as a uint8_t array
std:: string childDET; 
std:: string ParentDET;

unsigned long lastTransmissionTime = 0;  // To manage timed transmissions
const unsigned long transmissionInterval = 5000;  // 5 seconds
// Function to convert an unsigned int to a binary string with leading zeros
std::string toBinary(unsigned int value, int bits) {
    return std::bitset<64>(value).to_string().substr(64 - bits, bits);  // Convert and trim to required bits
}

// Helper function to insert 32-bit Unix timestamp into a vector (little-endian format)
void insertUnixTimestamp(std::vector<uint8_t>& vec, uint32_t timestamp) {
    for (int i = 0; i < 4; i++) {
        vec.push_back((uint8_t)(timestamp >> (8 * i)));  // Little-endian order
    }
}

std::string binaryToHex(const std::string& binaryStr) {
    std::string hexStr;
    int len = binaryStr.length();

    // Iterate over every 4 bits and convert them to hex
    for (int i = 0; i < len; i += 4) {
        std::string fourBits = binaryStr.substr(i, 4); // Extract 4 bits
        unsigned int decimalValue = std::stoi(fourBits, nullptr, 2); // Convert binary to decimal

        // Convert decimal to hexadecimal manually
        if (decimalValue < 10) {
            hexStr += '0' + decimalValue; // 0-9
        } else {
            hexStr += 'A' + (decimalValue - 10); // A-F
        }
    }

    return hexStr;
}

// Helper function to convert std::string (hex) to uint8_t array
void hexStringToByteArray(const std::string& hexStr, uint8_t* byteArray, size_t byteArrayLen) {
    for (size_t i = 0; i < byteArrayLen; ++i) {
        std::string byteString = hexStr.substr(2 * i, 2);
        byteArray[i] = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
    }
}

// Helper function to print a vector of uint8_t as hex values
void printVectorHex(const std::vector<uint8_t>& vec, const char* label) {
    Serial.print(label);
    for (const auto& byte : vec) {
        Serial.printf("%02X ", byte);
    }
    Serial.println();
}


// Key variables for private and public key
uint8_t privateKey[32];
uint8_t publicKey[32];


uint8_t parentPrivateKey[32];
uint8_t parentPublicKey[32];
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

std:: string det_orchid( unsigned int hda,  unsigned int raa,  unsigned int ipv6, unsigned int suitid, uint8_t publicKey[32], bool isParent){
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

     std::string h_orchid_left_hex = binaryToHex(h_orchid_left_bin);

    // Combine the binary ORCHID left side and the hashed right side
    std::string h_orchid = h_orchid_left_hex + h_hash_str;

    // re-convert the h_orchid_left_bin to make sure of the values. 

    // Format the ORCHID into an IPv6 address-like string
    std::string formatted_orchid;
    for (size_t i = 0; i < h_orchid.length(); i += 4) {
        formatted_orchid += h_orchid.substr(i, 4) + ":";
    }
    formatted_orchid.pop_back();  // Remove the trailing ':'

    //String test = binaryToHex(h_orchid);

    Serial.println();
    if(isParent){

    Serial.println("Parent DET ORCHID:" +String(formatted_orchid.c_str()));
     Serial.println("Parent Public Key:");
    }else{
    Serial.println("DET ORCHID:" +String(formatted_orchid.c_str()));
    Serial.println("Child Public Key:");
    }
           for (int i = 0; i < 32; i++) {
        Serial.printf("%02X ", publicKey[i]);
    }
  Serial.println();


    // Serial.println(h_orchid);
    // Serial.println(test);
    return h_orchid;

}


// Function to Create Payload (F3411 Messages)
std::vector<uint8_t> createPayload(const uint8_t *det, size_t detLen) {
    std::vector<uint8_t> payload;

    // Add Example F3411 Messages (25 bytes per message)
    uint8_t f3411Message[25] = {0};
    for (int i = 0; i < 25; i++) f3411Message[i] = random(0, 256);
    payload.insert(payload.end(), f3411Message, f3411Message + 25);

    // Add DET to Payload
    payload.insert(payload.end(), det, det + detLen);

    // Print the payload vector in hex
    printVectorHex(payload, "Payload (F3411 Messages): ");

    return payload;
}


std::vector<uint8_t> createDRIPLink(
    const uint8_t *parentDET, size_t parentDETLen,
    const uint8_t *det, size_t detLen,
    const uint8_t *childPublicKey, size_t publicKeyLen) {
    std::vector<uint8_t> dripLink;

    // For now, we will be generating Random DET for the Parent with Random Pair Keys. 

       // Get the current Unix timestamps
    uint32_t validNotBefore = getCurrentUnixTimestamp();  // Now
    uint32_t validNotAfter = validNotBefore + 300;  // Valid for 5 minutes

    // Insert timestamps into the DRIP link in little-endian format
    insertUnixTimestamp(dripLink, validNotBefore);
    insertUnixTimestamp(dripLink, validNotAfter);


    
    // Child DET (Drone's DET)
    dripLink.insert(dripLink.end(), det, det + detLen);

      // Child Public Key
    dripLink.insert(dripLink.end(), childPublicKey, childPublicKey + publicKeyLen);

    // Parent DET
    dripLink.insert(dripLink.end(), parentDET, parentDET + parentDETLen);

    printVectorHex(dripLink, "DRIP LINK BEFORE SIGNING: ");

    uint8_t parentSignature[64];
    // Sign the Child DET using the Parent’s private key
    Ed25519::sign(parentSignature, privateKey, publicKey, det, detLen);

    // Parent Signature
    dripLink.insert(dripLink.end(), parentSignature, parentSignature + 64);

       // Print the payload vector in hex
    printVectorHex(dripLink, "DRIP LINK : ");


    return dripLink;
}


std::vector<uint8_t> createWrapper(
    const std::vector<uint8_t> &payload, const uint8_t *det) {
    
    std::vector<uint8_t> wrapper;

    // Valid Not Before (current timestamp in seconds)
    uint32_t validNotBefore = millis() / 1000;
    wrapper.insert(wrapper.end(), (uint8_t*)&validNotBefore, (uint8_t*)&validNotBefore + 4);

    // Valid Not After (5 minutes later)
    uint32_t validNotAfter = validNotBefore + 300;
    wrapper.insert(wrapper.end(), (uint8_t*)&validNotAfter, (uint8_t*)&validNotAfter + 4);

    // Add payload (F3411 messages, 25–100 bytes)
    wrapper.insert(wrapper.end(), payload.begin(), payload.end());

    // Add DET
    wrapper.insert(wrapper.end(), det, det + 16);

    printVectorHex(wrapper, "WRAPPER BEFORE SIGNING : ");

    // Sign the wrapper
    uint8_t signature[64];
    Ed25519::sign(signature, privateKey, publicKey, wrapper.data(), wrapper.size());

   
    // Add signature to the wrapper
    wrapper.insert(wrapper.end(), signature, signature + 64);
    printVectorHex(wrapper, "WRAPPER AFTER SIGNING : ");


    return wrapper;
}








void generateKeys(bool isParent){
  if(isParent){
   Ed25519::generatePrivateKey(parentPrivateKey);
   Ed25519::derivePublicKey(parentPublicKey, parentPrivateKey);
   return; 
  }
  Ed25519::generatePrivateKey(privateKey);
  Ed25519::derivePublicKey(publicKey, privateKey);

}









void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);

// Connect to Wi-Fi
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.println("Connecting to WiFi...");
    }
    Serial.println("Connected to WiFi.");

    // Initialize time from NTP server
    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

    // Wait for time to be set
    struct tm timeInfo;
    if (!getLocalTime(&timeInfo)) {
        Serial.println("Failed to obtain time");
        return;
    }

    Serial.println("Time synchronized:");
    Serial.println(&timeInfo, "%Y-%m-%d %H:%M:%S");

  generateKeys(true);
  generateKeys(false);
  
    // Setup the constat values. :
    det.prefix = 0x2001003; 
    det.raa = 16376; 
    det.hda = 1025;
    det.suiteID = 5; 
    

     
    
  
}

uint32_t getCurrentUnixTimestamp() {
    time_t now;
    time(&now);  // Get the current time in seconds since the epoch
    return static_cast<uint32_t>(now);
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
       
       ParentDET=  det_orchid (det.hda, det.raa, det.prefix, det.suiteID, parentPublicKey, true);
       childDET =  det_orchid (det.hda, det.raa, det.prefix, det.suiteID, publicKey,false);

        
        // Convert std::string DETs to uint8_t arrays
        uint8_t parentDETArray[16];
        uint8_t childDETArray[16];
        hexStringToByteArray(ParentDET, parentDETArray, sizeof(parentDETArray));
        hexStringToByteArray(childDET, childDETArray, sizeof(childDETArray));
        
        // Create Payload and DRIP Link
        std::vector<uint8_t> payload = createPayload(parentDETArray, sizeof(parentDETArray));
        std::vector<uint8_t> dripLink = createDRIPLink(
            parentDETArray, sizeof(parentDETArray), 
            childDETArray, sizeof(childDETArray), 
            publicKey, sizeof(publicKey)
        );

         // Create Wrapper
        std::vector<uint8_t> wrapper = createWrapper(payload, childDETArray);
            


    }




}
