#include <Ed25519.h>
#include <RNG.h>
#include <KeccakP-1600-SnP.h>
#include "KeccakP-1600-inplace32BI.c"  // Include the core Keccak permutation

// Define the key variables
uint8_t privateKey[32];
uint8_t publicKey[32];

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

// Example function to generate DET using cSHAKE128
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

void setup() {
    Serial.begin(115200);
    Serial.println("Starting DET generation...");

    // Total heap size
    Serial.print("Total heap size: ");
    Serial.println(ESP.getHeapSize());

    // Initialize the random number generator and generate private key
    for (int i = 0; i < sizeof(privateKey); i++) {
        privateKey[i] = random(0, 256); 
    }

    // Generate the public key from the private key
    Ed25519::derivePublicKey(publicKey, privateKey);
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

    // Print final free heap memory
    Serial.print("Final free heap: ");
    Serial.println(ESP.getFreeHeap());

    delay(5000);  // Delay for 5 seconds before repeating
}

// Function to create a DRIP manifest (incomplete, for future implementation)
void createManifest(uint8_t* previousManifestHash, uint8_t* currentManifestHash, uint8_t* dripLinkHash, std::vector<uint8_t*> astmMessageHashes) {
    // Initialize cSHAKE128 for manifest creation
    SHAKE128 shake;
    uint8_t evidence[64];  // For storing the evidence hash

    // Further implementation needed based on the specifics of the manifest process
}
