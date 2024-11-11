#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes_header.h"

                                    //---Implementation of ecb---//
                                    
//Encryption of ecb
                                
void ecb_encryption(const char *input_file_name, const char *ciphertext_file_name, unsigned char key[16]){
     word **round_keys = key_expansion(key);//all round keys


    // open input file in read mode and output file in write mode
    FILE *input_file = fopen(input_file_name, "rb");
    FILE *ciphertext_file = fopen(ciphertext_file_name, "wb");

    if (input_file == NULL || ciphertext_file == NULL) {
        perror("Error opening file");
    }

    
    unsigned char buffer[16];  // Buffer to store 16 bytes
    size_t bytesRead;          // Number of bytes actually read
    
    
    // Read the file in chunks of 16 bytes
    while ((bytesRead = fread(buffer, 1, 16, input_file)) == 16) {
            
       //Encryption
       unsigned char **cipher_text = encryption(buffer, round_keys);
       
       // Write data column by column
       for (size_t col = 0; col < 4; col++) {
            for (size_t row = 0; row < 4; row++) {
                 fwrite(&cipher_text[row][col], 1, 1, ciphertext_file);
            }
       }
       }
       
    //padding
    for(size_t j = bytesRead; j<16; j++){
        buffer[j] = (unsigned char)(16-bytesRead);
    }
            
    //Encryption
    unsigned char **cipher_text = encryption(buffer, round_keys);
       
    // Write data column by column
    for (size_t col = 0; col < 4; col++) {
         for (size_t row = 0; row < 4; row++) {
             fwrite(&cipher_text[row][col], 1, 1, ciphertext_file);
         }
    }
        

    // Close the file
    fclose(input_file);
    fclose(ciphertext_file);
}




//Decryption of ecb
                                    
void ecb_decryption(const char *ciphertext_file_name, const char *plaintext_file_name_after_dec, unsigned char key[16]){
     word **round_keys = key_expansion(key);//all round keys
    

    // 
    FILE *ciphertext_file = fopen(ciphertext_file_name, "r");
    FILE *plaintext_file_after = fopen(plaintext_file_name_after_dec, "wb");
    if (ciphertext_file == NULL || plaintext_file_after == NULL) {
        perror("Error opening file");
    }

    
    unsigned char buffer[16];  // Buffer to store 16 bytes
    size_t bytesRead;          // Number of bytes actually read
    unsigned char temp[16] = {0};
    
    
    // Read the file in chunks of 16 bytes
    while ((bytesRead = fread(buffer, 1, 16, ciphertext_file)) > 0) {           
       //decryption
       unsigned char **plain_text = decryption(buffer, round_keys);
       
       // Write data column by column
       for (size_t col = 0; col < 4; col++) {
            for (size_t row = 0; row < 4; row++) {
                 fwrite(&plain_text[row][col], 1, 1, plaintext_file_after);
            }
       }
    }

    // Close the file
    fclose(ciphertext_file);
    fclose(plaintext_file_after);
}


int main() {
    // Example input and output file names
    const char *input_file_name = "demo.txt";
    const char *ciphertext_file_name = "ciphertext.txt";
    const char *plaintext_file_name_before_dec = "plaintext_before_dec.txt";
    const char *plaintext_file_name_after_dec = "plaintext_after_dec.txt";
    
    //key
    unsigned char key[16] ={0x00, 0x01, 0x02, 0x03,
			 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0a, 0x0b,
			 0x0c, 0x0d, 0x0e, 0x0f}; 
			 
    ecb_encryption(input_file_name, ciphertext_file_name, key);	 
    ecb_decryption(ciphertext_file_name, plaintext_file_name_after_dec, key);
    
			 
return 0;			 
}	


















                                  

