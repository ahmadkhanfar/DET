#include <Ed25519.h>
#include <RNG.h>

#include <KeccakP-1600-SnP.h>
#include "KeccakP-1600-inplace32BI.c" // Include the core Keccak permutation

// Custom implementation to absorb data and squeeze output using Keccak P-1600
// Define the curve

uint8_t privateKey[32];
uint8_t publicKey[32];


// Initialize the ECC object

void cshake128(const uint8_t *input, size_t inputLen, const uint8_t *customization, size_t customLen, uint8_t *output, size_t outputLen) {
    KeccakP1600_state keccakState;  // Adjust the type name

    // Initialize the state
    KeccakP1600_StaticInitialize();
    KeccakP1600_Initialize(&keccakState);
    
    // Absorb customization string (N) and input data
    KeccakP1600_AddBytes(&keccakState, customization, 0, customLen);
    KeccakP1600_AddBytes(&keccakState, input, 0, inputLen);
    
    // Apply permutation
    KeccakP1600_Permute_24rounds(&keccakState);
    
    // Extract the output
    KeccakP1600_ExtractBytes(&keccakState, output, 0, outputLen);

    // Print free heap memory
    Serial.print("Free heap during cSHAKE128: ");
    Serial.println(ESP.getFreeHeap());
}

// Example of using cSHAKE128 to generate DET
String det_cshake128(const uint8_t *publicKey, size_t pubKeyLen, uint16_t raa, uint16_t hda, const uint8_t *hi, size_t hiLen) {
    uint8_t output[32];  // 256-bit output
    String b_prefix = "0010000000000001000000000011";
    String b_hid = String(raa, BIN) + String(hda, BIN);
    String b_ogaid = "00000101";
    String input_data = b_prefix + b_hid + b_ogaid;

    // Perform cSHAKE128 on the input data with the public key as the customization string
    cshake128((const uint8_t *)input_data.c_str(), input_data.length(), publicKey, pubKeyLen, output, sizeof(output));
    
    // Convert the hash output to a hex string
    String det = "";
    for (int i = 0; i < sizeof(output); i++) {
        det += String(output[i], HEX);
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
// Initialize the random number generator
  // Generate a private key using Crypto's RNG
    for (int i = 0; i < sizeof(privateKey); i++) {
        privateKey[i] = random(0, 256); 
    }

    // Generate the public key from the private key
    Ed25519::derivePublicKey(publicKey, privateKey);


}

void loop() {
    // Your loop code here, if needed

    // Example RAA and HDA
    uint16_t RAA = 16376; // RAA
    uint16_t HDA = 1025; // WMU




  String det = det_cshake128(publicKey , sizeof(publicKey), RAA, HDA, privateKey, sizeof(privateKey));
    Serial.println("Generated DET: " + det);

        // Print the keys in hexadecimal format
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



    delay(5000);
    


}

















// TESTING 

void createManifest(uint8_t* previousManifestHash, uint8_t* currentManifestHash, uint8_t* dripLinkHash, std::vector<uint8_t*> astmMessageHashes) {
    // Initialize cSHAKE128
    SHAKE128 shake;
    uint8_t evidence[64]; // For storing the evidence hash


}


