#include <Ed25519.h>
#include <RNG.h>
#include <KeccakP-1600-SnP.h>
#include "KeccakP-1600-inplace32BI.c"  // Include the core Keccak permutation
#include <vector>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
unsigned long lastTransmissionTime = 0;  // To manage timed transmissions
const unsigned long transmissionInterval = 5000;  // 5 seconds



 // Example RAA and HDA
uint16_t RAA = 16376;  // Example RAA
uint16_t HDA = 1025;   // Example HDA (WMU)

// Define BLE characteristics for broadcasting values
BLECharacteristic *detCharacteristic;
BLECharacteristic *dripLinkCharacteristic;
BLECharacteristic *wrapperCharacteristic;
BLECharacteristic *systemInfoCharacteristic;

// Define key variables for DET, DRIP Link, and Wrapper generation
uint8_t privateKey[32];
uint8_t publicKey[32];
uint8_t parentDET[16];  // Example Parent DET
uint8_t parentSignature[64];  // Signature by Parent
String det_str;

void printMemoryAndCPUInfo() {
    // Print total heap size
    Serial.print("Total Heap Size: ");
    Serial.println(ESP.getHeapSize());

    // Print free heap memory
    Serial.print("Free Heap Memory: ");
    Serial.println(ESP.getFreeHeap());

    // Print minimum free heap memory ever
    Serial.print("Minimum Free Heap Memory: ");
    Serial.println(ESP.getMinFreeHeap());

    // Print CPU frequency (in MHz)
    Serial.print("CPU Frequency: ");
    Serial.println(ESP.getCpuFreqMHz());
}


// Function to calculate CPU load
void printCPULoad() {
    TaskStatus_t *taskArray;
    UBaseType_t arraySize;
    uint32_t totalRunTime;

    arraySize = uxTaskGetNumberOfTasks();
    taskArray = (TaskStatus_t *)pvPortMalloc(arraySize * sizeof(TaskStatus_t));
    if (taskArray != NULL) {
        arraySize = uxTaskGetSystemState(taskArray, arraySize, &totalRunTime);
        totalRunTime /= 100; // Convert to percentage

        for (UBaseType_t i = 0; i < arraySize; i++) {
            Serial.printf("Task %s CPU Usage: %u%%\n", taskArray[i].pcTaskName, taskArray[i].ulRunTimeCounter / totalRunTime);
        }

        vPortFree(taskArray); // Free the memory allocated to the task array
    }
}

std::vector<uint8_t> createDRIPLink(
    const uint8_t *parentDET, size_t parentDETLen,
    const uint8_t *det, size_t detLen,
    const uint8_t *childPublicKey, size_t publicKeyLen) {
    
    std::vector<uint8_t> dripLink;

    // Valid Not Before (current timestamp in seconds)
    uint32_t validNotBefore = millis() / 1000;  
    dripLink.insert(dripLink.end(), (uint8_t*)&validNotBefore, (uint8_t*)&validNotBefore + 4);

    // Valid Not After (5 minutes later, for example)
    uint32_t validNotAfter = validNotBefore + 300; 
    dripLink.insert(dripLink.end(), (uint8_t*)&validNotAfter, (uint8_t*)&validNotAfter + 4);

    // Parent DET
    dripLink.insert(dripLink.end(), parentDET, parentDET + parentDETLen);

    // Child DET (Drone's DET)
    dripLink.insert(dripLink.end(), det, det + detLen);

    // Child Public Key
    dripLink.insert(dripLink.end(), childPublicKey, childPublicKey + publicKeyLen);

    // Sign the Child DET using the Parent’s private key
    Ed25519::sign(parentSignature, privateKey, publicKey, det, detLen);

    // Parent Signature
    dripLink.insert(dripLink.end(), parentSignature, parentSignature + 64);

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
String det_cshake128(const uint8_t *publicKey, size_t pubKeyLen, uint16_t raa, uint16_t hda) {
    uint8_t output[32];  // DET is 128 bits (16 bytes), but cSHAKE outputs 256 bits (32 bytes)

    // Prefix, HID, Suite ID
    String b_prefix = "0010000000000001000000000011";  // Example Prefix
    String b_hid = String(raa, BIN);  // Convert RAA to 14-bit binary
    while (b_hid.length() < 14) b_hid = "0" + b_hid;  // Ensure 14-bit length

    String b_hid_hda = String(hda, BIN);  // Convert HDA to 14-bit binary
    while (b_hid_hda.length() < 14) b_hid_hda = "0" + b_hid_hda;  // Ensure 14-bit length

    String b_ogaid = "00000000";  // **8-bit** Suite ID 
    String input_data = b_prefix + b_hid + b_hid_hda + b_ogaid + String((char *)publicKey);  // Include public key

    // Customization String (Context ID)
    uint8_t contextID[] = { 0x00B5, 0xA69C, 0x795D, 0xF5D5, 0xF008, 0x7F56, 0x843F, 0x2C40 };  // Context ID for DET

    // Perform cSHAKE128
    cshake128((const uint8_t *)input_data.c_str(), input_data.length(), contextID, sizeof(contextID), output, sizeof(output));

    // Convert 128 bits (16 bytes) of the output to a hex string
    uint8_t det[16];
    memcpy(det, output, 16);  // Take 128 bits (16 bytes)

    String det_str = "";
    for (int i = 0; i < sizeof(det); i++) {
        if (det[i] < 0x10) det_str += "0";  // Add leading zero if necessary
        det_str += String(det[i], HEX);  // Convert byte to hexadecimal
    }

    return det_str;
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

    // Sign the wrapper
    uint8_t signature[64];
    Ed25519::sign(signature, privateKey, publicKey, wrapper.data(), wrapper.size());

    // Add signature to the wrapper
    wrapper.insert(wrapper.end(), signature, signature + 64);

    return wrapper;
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

  esp_ble_gap_set_prefered_default_phy(ESP_BLE_GAP_PHY_2M, ESP_BLE_GAP_PHY_2M);
 // to ensure BT5  Physical layer is used 

    BLEDevice::init("ESP32-DRIP");

    BLEServer *pServer = BLEDevice::createServer();
    BLEService *dripService = pServer->createService(BLEUUID("12345678-1234-5678-1234-56789abcdef0"));

    // Create characteristics for DET, DRIP Links, Wrapper, and System Info
    detCharacteristic = dripService->createCharacteristic(
                            BLEUUID("12345678-1234-5678-1234-56789abcdef1"),
                            BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
    
    dripLinkCharacteristic = dripService->createCharacteristic(
                            BLEUUID("12345678-1234-5678-1234-56789abcdef2"),
                            BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
    
    wrapperCharacteristic = dripService->createCharacteristic(
                            BLEUUID("12345678-1234-5678-1234-56789abcdef3"),
                            BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
    
    systemInfoCharacteristic = dripService->createCharacteristic(
                            BLEUUID("12345678-1234-5678-1234-56789abcdef4"),
                            BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
    
    // Start the service
    dripService->start();
    
    // Start advertising the service
    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();

    pAdvertising->setMinPreferred(0x06);  // Set interval for extended advertising (Bluetooth 5 feature)
    pAdvertising->setMaxPreferred(0x12);  // Max interval for extended advertising
    pAdvertising->addServiceUUID(dripService->getUUID());
    pAdvertising->start();










    // Total heap size
    Serial.print("Total heap size: ");
    Serial.println(ESP.getHeapSize());

    // Initialize random private key and generate public key
    for (int i = 0; i < sizeof(privateKey); i++) {
        privateKey[i] = random(0, 256); 
    }
    Ed25519::derivePublicKey(publicKey, privateKey);
    
    // Memory usage after key generation
    Serial.print("Free Heap Memory after Key Generation: ");
    Serial.println(ESP.getFreeHeap());

      // Generate the DET once and reuse it
    det_str = det_cshake128(publicKey, sizeof(publicKey), RAA, HDA);
 
}

void loop() {
    // Only send messages every 5 seconds
    unsigned long currentTime = millis();
    if (currentTime - lastTransmissionTime >= transmissionInterval) {
        lastTransmissionTime = currentTime;
   Serial.println("Generated DET: " + det_str);
        // Convert the string DET back to byte array (assuming it's 16 bytes)
        uint8_t det[16];
        for (int i = 0; i < 16; i++) {
            det[i] = strtol(det_str.substring(2*i, 2*i + 2).c_str(), NULL, 16);
        }

        // Create payload containing the DET and public key
        std::vector<uint8_t> payload = createPayload(det, sizeof(det), publicKey, sizeof(publicKey));

        // Create DRIP Links with parent DET and signature
        std::vector<uint8_t> dripLink = createDRIPLink(parentDET, sizeof(parentDET), det, sizeof(det));

        // Memory usage after DRIP Link creation
        Serial.print("Free Heap Memory after DRIP Link Creation: ");
        Serial.println(ESP.getFreeHeap());

        // Create and sign the Wrapper (payload)
        uint8_t signature[64];
        createWrapper(privateKey, payload, signature);

        // Combine payload and signature into the full Wrapper
         std::vector<uint8_t> wrapper;
        wrapper.insert(wrapper.end(), payload.begin(), payload.end());  // Add payload to Wrapper
        wrapper.insert(wrapper.end(), signature, signature + 64);  // Add signature to Wrapper


        // Print the DRIP Link
        Serial.println("Generated DRIP Link:");
        for (size_t i = 0; i < dripLink.size(); i++) {
            Serial.print(dripLink[i], HEX);
            Serial.print(" ");
        }
        Serial.println();

        // Print the signed payload (Wrapper)
        Serial.println("Signed Wrapper:");
        for (int i = 0; i < wrapper.size(); i++) {
            Serial.print(wrapper[i], HEX);
            Serial.print(" ");
        }
        Serial.println();



        // Update BLE characteristics
        detCharacteristic->setValue(det, sizeof(det));
        detCharacteristic->notify();  // Notify connected clients
        
        dripLinkCharacteristic->setValue((uint8_t*)&dripLink[0], dripLink.size());
        dripLinkCharacteristic->notify();
        
        wrapperCharacteristic->setValue((uint8_t*)&wrapper[0], wrapper.size());
        wrapperCharacteristic->notify();
        
        // Broadcast system info (heap and CPU)
        String systemInfo = "Heap: " + String(ESP.getFreeHeap()) + " / CPU: " + String(ESP.getCpuFreqMHz());
        systemInfoCharacteristic->setValue(systemInfo.c_str());
        systemInfoCharacteristic->notify();


        // Print memory and CPU information
        Serial.print("Final free heap: ");
        Serial.println(ESP.getFreeHeap());
        printMemoryAndCPUInfo();
    }

    delay(100);  // Small delay to avoid excessive CPU usage
}
