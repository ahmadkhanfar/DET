#include <Ed25519.h>
#include <RNG.h>
#include <KeccakP-1600-SnP.h>
#include "KeccakP-1600-inplace32BI.c"  // Include the core Keccak permutation
#include <vector>

// Define key variables for DET, DRIP Link, and Wrapper generation
uint8_t privateKey[32];
uint8_t publicKey[32];
uint8_t parentDET[16];  // Example Parent DET
uint8_t parentSignature[64];  // Signature by Parent

// Function to create DRIP Links
std::vector<uint8_t> createDRIPLink(const uint8_t *parentDET, size_t parentDETLen, const uint8_t *det, size_t detLen) {
    std::vector<uint8_t> dripLink;

    // Add Parent DET to the DRIP Link
    for (size_t i = 0; i < parentDETLen; i++) {
        dripLink.push_back(parentDET[i]);
    }

    // Add Child DET (the drone's DET)
    for (size_t i = 0; i < detLen; i++) {
        dripLink.push_back(det[i]);
    }

    // Sign the Child DET with the Parent's private key
    Ed25519::sign(parentSignature, privateKey, det, detLen);

    // Add Parent Signature to the DRIP Link
    for (int i = 0; i < 64; i++) {
        dripLink.push_back(parentSignature[i]);
    }

    return dripLink;
}

// Custom implementation to absorb data and squeeze output using Keccak P-1600 for cSHAKE128
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

    // Extract the output
    KeccakP1600_ExtractBytes(&keccakState, output, 0, outputLen);

    // Print free heap memory
    Serial.print("Free heap during cSHAKE128: ");
    Serial.println(ESP.getFreeHeap());
}

// Function to generate DET using cSHAKE128
String det_cshake128(const uint8_t *publicKey, size_t pubKeyLen, uint16_t raa, uint16_t hda, const uint8_t *hi, size_t hiLen) {
    uint8_t output[16];  // DET is 128 bits (16 bytes)

    // Prefix, HID, Suite ID
    String b_prefix = "0010000000000001000000000011";  // Example Prefix
    String b_hid = String(raa, BIN);  // Convert RAA to 14-bit binary
    while (b_hid.length() < 14) b_hid = "0" + b_hid;  // Ensure 14-bit length

    String b_hid_hda = String(hda, BIN);  // Convert HDA to 14-bit binary
    while (b_hid_hda.length() < 14) b_hid_hda = "0" + b_hid_hda;  // Ensure 14-bit length

    String b_ogaid = "00000101";  // Example Suite ID (5 bits)
    String input_data = b_prefix + b_hid + b_hid_hda + b_ogaid + String((char *)publicKey);  // Include public key

    // Customization String (Context ID)
    uint8_t contextID[] = { 0x00B5, 0xA69C, 0x795D, 0xF5D5, 0xF008, 0x7F56, 0x843F, 0x2C40 };  // Context ID for DET

    // Perform cSHAKE128
    cshake128((const uint8_t *)input_data.c_str(), input_data.length(), contextID, sizeof(contextID), output, sizeof(output));

    // Convert lower 64 bits of the output to a hex string
    uint8_t lower_half_det[8];
    memcpy(lower_half_det, output + 8, 8);  // Take the lower half (64 bits)
    
    String det = "";
    for (int i = 0; i < sizeof(lower_half_det); i++) {
        det += String(lower_half_det[i], HEX);
    }

    // Print free heap memory after DET creation
    Serial.print("Free heap after DET creation: ");
    Serial.println(ESP.getFreeHeap());

    return det;
}

// Function to sign the payload (Wrapper)
void createWrapper(uint8_t *privateKey, const std::vector<uint8_t> &payload, uint8_t *signature) {
    // Create a buffer for the signature
    uint8_t signatureBuffer[64];

    // Sign the payload using the Ed25519 private key
    Ed25519::sign(signatureBuffer, privateKey, payload.data(), payload.size());

    // Copy the generated signature to the provided buffer
    memcpy(signature, signatureBuffer, 64);

    Serial.println("Wrapper created with signature:");
    for (int i = 0; i < 64; i++) {
        Serial.print(signature[i], HEX);
        Serial.print(" ");
    }
    Serial.println();
}

// Function to generate the payload (B-RID and DET)
std::vector<uint8_t> createPayload(const uint8_t *det, size_t detLen, const uint8_t *publicKey, size_t publicKeyLen) {
    std::vector<uint8_t> payload;

    // Append DET to the payload
    for (size_t i = 0; i < detLen; i++) {
        payload.push_back(det[i]);
    }

    // Append public key to the payload
    for (size_t i = 0; i < publicKeyLen; i++) {
        payload.push_back(publicKey[i]);
    }

    return payload;
}

void setup() {
    Serial.begin(115200);
    Serial.println("Starting DET generation...");

    // Total heap size
    Serial.print("Total heap size: ");
    Serial.println(ESP.getHeapSize());

    // Initialize random private key and generate public key
    for (int i = 0; i < sizeof(privateKey); i++) {
        privateKey[i] = random(0, 256); 
    }
    Ed25519::derivePublicKey(publicKey, privateKey);

    // Example DET (16 bytes)
    uint8_t det[16] = {0x00, 0xB5, 0xA6, 0x9C, 0x79, 0x5D, 0xF5, 0xD5, 0xF0, 0x08, 0x7F, 0x56, 0x84, 0x3F, 0x2C, 0x40};

    // Create payload containing the DET and public key
    std::vector<uint8_t> payload = createPayload(det, sizeof(det), publicKey, sizeof(publicKey));

    // Create DRIP Links with parent DET and signature
    std::vector<uint8_t> dripLink = createDRIPLink(parentDET, sizeof(parentDET), det, sizeof(det));

    // Create and sign the Wrapper (payload)
    uint8_t signature[64];
    createWrapper(privateKey, payload, signature);

    // Print the DRIP Link
    Serial.println("Generated DRIP Link:");
    for (size_t i = 0; i < dripLink.size(); i++) {
        Serial.print(dripLink[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    // Print the signed payload (Wrapper)
    Serial.println("Signed Wrapper:");
    for (int i = 0; i < payload.size(); i++) {
        Serial.print(payload[i], HEX);
        Serial.print(" ");
    }
    Serial.println();
}

void loop() {
    // Example RAA and HDA
    uint16_t RAA = 16376;  // Example RAA
    uint16_t HDA = 1025;   // Example HDA (WMU)

    // Generate the DET
    String det = det_cshake128(publicKey, sizeof(publicKey), RAA, HDA, privateKey, sizeof(privateKey));
    Serial.println("Generated DET: " + det);

    // Print the private and public keys in hexadecimal format
    Serial.print("Private Key: ");
    for (int i = 0; i < 32; i++) {
        Serial.print(privateKey[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    Serial.print("Public Key: ");
    for (int i = 0; i < 32; i++) {
        Serial.print(publicKey[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

     Serial.print("Final free heap: ");
    Serial.println(ESP.getFreeHeap());

    delay(5000);  // Repeat every 5 seconds
}
