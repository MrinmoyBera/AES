#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes_header.h"

                                    //---Implementation of cfb--//
                                    
//Encryption of cfb
                                
void cfb_encryption(const char *input_file_name, const char *ciphertext_file_name, unsigned char key[16]){
     word **round_keys = key_expansion(key);//all round keys
     
     //random array that can be add to the first message chunk(16-bytes)
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03,
			 0x04, 0x05, 0x06, 0x07,
			 0x28, 0x0a, 0x0c, 0x0b,
			 0x1c, 0x0d, 0x0e, 0x0f};


    // open input file in read mode and output file in write mode
    FILE *input_file = fopen(input_file_name, "rb");
    FILE *ciphertext_file = fopen(ciphertext_file_name, "wb");

    if (input_file == NULL || ciphertext_file == NULL) {
        perror("Error opening file");
    }
    // Write iv into the ciphertext.txt file
    fwrite(iv, 1, 16, ciphertext_file);
    
    unsigned char buffer[16];  // Buffer to store 16 bytes
    size_t bytesRead;          // Number of bytes actually read
    unsigned char cipher_text[16];
    
    // Read the file in chunks of 16 bytes
    while ((bytesRead = fread(buffer, 1, 16, input_file)) == 16) {
       
       //Encrypted text
       unsigned char **encrypted_text = encryption(iv, round_keys);
       //xor between encrypted_text and plain_text
       for(int j=0; j<4; j++){
           for(int i=0; i<4; i++){
              cipher_text[i+4*j] = buffer[i+4*j] ^encrypted_text[i][j];
           }
       }
       
       //update variable iv by cipher_text
       for(int i=0; i<16; i++){
           iv[i] = cipher_text[i];
       }
          
       // Write cipher text into the ciphertext.txt file
       fwrite(cipher_text, 1, 16, ciphertext_file);
        
    }
    //For last buffer
    //padding
        for(size_t j = bytesRead; j<16; j++){
                buffer[j] = (unsigned char)(16 - bytesRead);
        }
       
       //Encrypted text
       unsigned char **encrypted_text = encryption(iv, round_keys);
       
       //xor between encrypted_text and plain_text
       for(int j=0; j<4; j++){
           for(int i=0; i<4; i++){
              cipher_text[i+4*j] = buffer[i+4*j] ^encrypted_text[i][j];
           }
       }
          
       // Write cipher text into the ciphertext.txt file
       fwrite(cipher_text, 1, 16, ciphertext_file);
       
    // Close the file
    fclose(input_file);
    fclose(ciphertext_file);
}




//Decryption of cfb
                                    
void cfb_decryption(const char *ciphertext_file_name, const char *plaintext_file_name_after_dec, unsigned char key[16]){

     word **round_keys = key_expansion(key);//all round keys

    FILE *ciphertext_file = fopen(ciphertext_file_name, "r");
    FILE *plaintext_file_after = fopen(plaintext_file_name_after_dec, "wb");
    if (ciphertext_file == NULL || plaintext_file_after == NULL) {
        perror("Error opening file");
    }
    
     
    //random array that can be add to the first message chunk(16-bytes)
    unsigned char iv[16];
    fread(iv,1,16,ciphertext_file);
    
    unsigned char buffer[16];  // Buffer to store 16 bytes
    size_t bytesRead;          // Number of bytes actually read
    unsigned char temp[16] = {0};
    
    
    // Read the file in chunks of 16 bytes
    while ((bytesRead = fread(buffer, 1, 16, ciphertext_file)) > 0) {           
       //Encrypted text
       unsigned char **encrypted_text = encryption(iv, round_keys);
       
       
       
       unsigned char plain_text[16];
       //xor between encrypted_text and plain_text
       for(int j=0; j<4; j++){
           for(int i=0; i<4; i++){
              plain_text[i+4*j] = buffer[i+4*j] ^encrypted_text[i][j];
           }
       }

       // Write cipher text into the ciphertext.txt file
       fwrite(plain_text, 1, 16, plaintext_file_after);   
       
       //update variable iv by cipher_text
       for(int i=0; i<16; i++){
           iv[i] = buffer[i];
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
			 
    cfb_encryption(input_file_name, ciphertext_file_name, key);	 
    cfb_decryption(ciphertext_file_name, plaintext_file_name_after_dec, key);
    
			 
return 0;			 
}
