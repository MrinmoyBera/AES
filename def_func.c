#include<stdio.h>
#include<stdlib.h>
#include <stdint.h>
#include "aes_header.h"
int NB = 4;
int NR = 10;
//For printing round key
void print_round_key(word **key_schedule) {
    for (int i = 0; i < 4; i++) {
         printf("%02x%02x%02x%02x",
               key_schedule[i]->w0,
               key_schedule[i]->w1,
               key_schedule[i]->w2,
               key_schedule[i]->w3);
       }
} 


//For Print the key schedule 
void print_key_schedule(word **key_schedule) {
    for (int i = 0; i < 44; i++) {
        
        if(i%4 == 0){
           printf("Round: %d ",(i/4));
        }
        printf("%02x%02x%02x%02x",
               key_schedule[i]->w0,
               key_schedule[i]->w1,
               key_schedule[i]->w2,
               key_schedule[i]->w3);
       if((i+1)%4 ==0){
          printf("\n");  
          }      
    }
}




//display cipher text
void display(unsigned char **s){
     for(int i=0; i<NB; i++){
         for(int j=0; j<NB; j++)
             printf("%02x",s[j][i]);   
     }
}

                              //--Key Expension--//
                          

              
// Define the function rotword
word *rotword(word *w) {
    /* 
    input : a word datatype variable
    
    output : The function RotWord() takes aword [w0 ,w1 ,w2 ,w3 ] as input, performs a cyclic permutation, and  returns the 
               word [w1 ,w2 ,w3 ,w0 ].
    */ 

    word *temp = (word *)malloc(sizeof(word));
    if (temp == NULL) {
        printf("Memory allocation failed!\n");
        exit(1);
    }
    // Apply rotated word
    temp->w0 = w->w1;
    temp->w1 = w->w2;
    temp->w2 = w->w3;
    temp->w3 = w->w0;
    return temp;
}

unsigned char s_box(unsigned char w) {

    /*
    input : a component of word variable.
    x= most significant four bits of input and y = least significant 4-bits .
    output : (x,y)-th element of the s_box matrix.
    */
    unsigned char x = w >> 4; // Extract the 4-most significant bits
    unsigned char y = w & 0x0F; // Extract the 4-least significant bits
    unsigned char s_b[16][16] = {
        {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
        {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
        {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
        {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
        {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
        {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
        {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
        {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
        {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
        {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
        {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
        {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
        {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
        {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
        {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
        {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
    };
   
    // Return corresponding  S-box value
    return s_b[x][y];
}

// Define subword operation
word *subword(word *w) {
    /*
     input : word 
     output : corresponding s_box substitution .
   */
    word *temp = (word *)malloc(sizeof(word));
    if (temp == NULL) {
        printf("Memory allocation failed!\n");
        exit(1);
    }

    // Apply s_box to each byte
    temp->w0 = s_box(w->w0);
    temp->w1 = s_box(w->w1);
    temp->w2 = s_box(w->w2);
    temp->w3 = s_box(w->w3);

    return temp;
}




// Defined round_constant
word *round_cons(int i){
    /*
    input  : round number 
    output : corresponding round constant
    */
    unsigned char rc_array[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    word *rc = (word *)malloc(sizeof(word));
    
    //store round constant of i-th round
    rc->w0 = rc_array[i-1];    
    rc->w1 = 0x00;
    rc->w2 = 0x00;
    rc->w3 = 0x00;     
    return rc ;  
}


// Defined XOR function between two words
word *xor_of_words(word *w1, word *w2) {
    /*
       input : two word w1 and w2.
       output : xor of each component of w1 and w2 .
    */
    word *temp = (word *)malloc(sizeof(word));
    if (temp == NULL) {
        printf("Memory allocation failed!\n");
        exit(1);
    }

    temp->w0 = w1->w0 ^ w2->w0;
    temp->w1 = w1->w1 ^ w2->w1;
    temp->w2 = w1->w2 ^ w2->w2;
    temp->w3 = w1->w3 ^ w2->w3;

    return temp;
}



// Defined key expansion 
word **key_expansion(unsigned char key[16]){
	word **all_keys = (word **)malloc(44*sizeof(word *));
	int i = 0;
	//store the master key into the word
	while(i < 4){
		all_keys[i] = (word *)malloc(sizeof(word));
                if (all_keys[i] == NULL) {
                    printf("Memory allocation failed!\n");
                    exit(1);
                }
		all_keys[i]->w0 = key[4*i];
		all_keys[i]->w1 = key[4*i + 1];
		all_keys[i]->w2 = key[4*i + 2];
		all_keys[i]->w3 = key[4*i + 3];
		i = i+1;
	}
	
	while(i < 4*11 ){
		word *temp = all_keys[i-1];
		//On last word of the previous key apply rotword next subword next xor with round constant .        
		if(i % 4 == 0){
			word *temp_rot = rotword(temp);
		        word *temp_sub = subword(temp_rot);
		        word *temp_rc = round_cons(i / 4);// (i/4) is the number of round
		        temp = xor_of_words(temp_sub, temp_rc);
		        
		        free(temp_rot); // Free the memory of the rotated word
		        free(temp_sub); // Free the memory of the substituted word
		        free(temp_rc); // Free the memory of the round constant word
		}
		//xor between temp and key component of previous round
		all_keys[i] = xor_of_words(all_keys[i-4], temp);
		
		if (i % 4 == 0) {
                    free(temp); // Free the memory of temp only if it was allocated in this loop
                }
                i = i+1;
	}
	return all_keys;             

}
                
                         //---End of Key Expansion---//
                         

                        //---Implementation of shift_row---//
                           

//shift one element from a particular row
unsigned char *shift_row_one(unsigned char *s){
     unsigned char *shift = malloc(NB*sizeof(unsigned char));
     shift[0] = s[1];
     shift[1] = s[2];
     shift[2] = s[3];
     shift[3] = s[0]; 
     return shift;
}                           
                           
                           
                           
unsigned char **shift_row(unsigned char **s){
    
    //Allocate memory for row pointer
    unsigned char **shift_result = malloc(NB * sizeof(unsigned char *)) ;
    //Allocate memory for each row
    for(int i=0; i<NB; i++){
        shift_result[i] = malloc(NB * sizeof(unsigned char));
    }
    
    
    // Shift rows
    shift_result[0] = s[0];  // No shift for the first row
    shift_result[1] = shift_row_one(s[1]);
    shift_result[2] = shift_row_one(shift_row_one(s[2]));
    shift_result[3] = shift_row_one(shift_row_one(shift_row_one(s[3])));
     
     /*
     //another way we can shift the row
     //shift operation
     //1st row
    for(int j=0; j<NB; j++){
        shift_result[0][j] = s[0][j];
    }
    //shift operation on all other row
    for(int i = 1; i< NB; i++){
        for(int j = 0; j<NB-i; j++){
            shift_result[i][j] = s[i][j+i]; 
        }
        for(int j=NB-i; j<NB; j++){
            shift_result[i][j] = s[i][j-(NB-i)];      
        }
    }*/

    return shift_result;
}


                  		//---End of shift_row ---//



                              //Implementation of mixcolumn

//Implementation of  x_time
unsigned char x_time(unsigned char a){
       unsigned x=a<<1;
       unsigned char y = a>>7;
          return x^(y*(0x1b)) ;//first left shift apply on a then xor with 1b
       }

//multiplication between a byte and 03
unsigned char multi_3(unsigned char a){
    return ((x_time(a))^a);
}
                       

unsigned char **mixcolumn(unsigned char **s){
    //Allocate memory for row pointer
    unsigned char **result = malloc(NB * sizeof(unsigned char *)) ;
    //Allocate memory for each row
    for(int i=0; i<NB; i++){
        result[i] = malloc(NB * sizeof(unsigned char));
    }
    //1st column
    result[0][0] = (x_time(s[0][0]))^(multi_3(s[1][0]))^(s[2][0])^(s[3][0]);
    result[1][0] = (s[0][0])^(x_time(s[1][0]))^(multi_3(s[2][0]))^(s[3][0]);   
    result[2][0] = (s[0][0])^(s[1][0])^(x_time(s[2][0]))^(multi_3(s[3][0]));
    result[3][0] = (multi_3(s[0][0]))^(s[1][0])^(s[2][0])^(x_time(s[3][0]));
    
    //2nd column
    result[0][1] = (x_time(s[0][1]))^(multi_3(s[1][1]))^(s[2][1])^(s[3][1]);
    result[1][1] = (s[0][1])^(x_time(s[1][1]))^(multi_3(s[2][1]))^(s[3][1]);
    result[2][1] = (s[0][1])^(s[1][1])^(x_time(s[2][1]))^(multi_3(s[3][1]));
    result[3][1] = (multi_3(s[0][1]))^(s[1][1])^(s[2][1])^(x_time(s[3][1]));
    
    //3rd column
    result[0][2] = (x_time(s[0][2]))^(multi_3(s[1][2]))^(s[2][2])^(s[3][2]);
    result[1][2] = (s[0][2])^(x_time(s[1][2]))^(multi_3(s[2][2]))^(s[3][2]);
    result[2][2] = (s[0][2])^(s[1][2])^(x_time(s[2][2]))^(multi_3(s[3][2]));
    result[3][2] = (multi_3(s[0][2]))^(s[1][2])^(s[2][2])^(x_time(s[3][2]));
    
    //4th column
    result[0][3] = (x_time(s[0][3]))^(multi_3(s[1][3]))^(s[2][3])^(s[3][3]);
    result[1][3] = (s[0][3])^(x_time(s[1][3]))^(multi_3(s[2][3]))^(s[3][3]);
    result[2][3] = (s[0][3])^(s[1][3])^(x_time(s[2][3]))^(multi_3(s[3][3]));
    result[3][3] = (multi_3(s[0][3]))^(s[1][3])^(s[2][3])^(x_time(s[3][3]));
    
    
    return result;
}



                          //---End of mix_column---//
                          
                          
                         //---Implementation of sub_bytes---//
          
unsigned char **sub_bytes(unsigned char **s){
    //Allocate memory for row pointer
    unsigned char **sub_result = malloc(NB * sizeof(unsigned char *)) ;
    //Allocate memory for each row
    for(int i=0; i<NB; i++){
        sub_result[i] = malloc(NB * sizeof(unsigned char));
    }
    
    //apply s_box to each byte of the State
    for(int i=0; i<NB; i++){
        for(int j=0; j<NB; j++){
            sub_result[i][j] = s_box(s[i][j]);//s_box on (i,j)-th cell
        }
    }
    
    return sub_result;
    
    } 

                       //---End of sub_bytes---//



                      //---Implementation of AddRoundkey function---//

unsigned char **add_round_key(unsigned char **s, word **w){

     //Allocate memory for row pointer
    unsigned char **result = malloc(NB * sizeof(unsigned char *)) ;
    //Allocate memory for each row
    for(int i=0; i<NB; i++){
        result[i] = malloc(NB * sizeof(unsigned char));
    }
   
    for(int i=0; i<NB; i++){
        result[0][i] = (s[0][i])^(w[i]->w0);
        result[1][i] = (s[1][i])^(w[i]->w1);
        result[2][i] = (s[2][i])^(w[i]->w2);
        result[3][i] = (s[3][i])^(w[i]->w3);
    }
    
    return result;

}

                    //---End of add_round_key---//
                    

                //---Implementation of cipher---// 

unsigned char **encryption(unsigned char *in, word ** w){
     
     int i,j;
     //convert one-dimension input array into a two dimension state array
     
     //Allocate memory for row pointer
     unsigned char **state = malloc(NB * sizeof(unsigned char *)) ;
     //Allocate memory for each row
     for(int i=0; i<NB; i++){
        state[i] = malloc(NB * sizeof(unsigned char));
     }   
     //apply convertion rule (i,j) -> i+4*j   
     for(i=0; i<NB; i++){
         for(j=0; j<NB; j++){
             state[i][j] = in[i+4*j];
         }
     }
     //print input
     printf("\nround[ 0 ].input    ");
     display(state);
     
     
     //defined a tempurary word memomry for storing round key in each round
     word **w_temp = (word **)malloc(NB*sizeof(word *));
     //storing given key
     for(i = 0;i<NB; i++){
         w_temp[i] = w[i];
     }
     
     //print round key
     printf("\nround[ 0 ].k_sch    ");
     print_round_key(w_temp);
     
     //perform add_round_key operation 
     state = add_round_key(state, w_temp) ;
     //print the input of round 1
     printf("\nround[ 1 ].start    ");
     display(state);
     
     for(int round = 1; round<NR; round++){
	 state = sub_bytes(state) ;
	 
	 //print after apply subbytes operation
	 printf("\nround[ %d ].s_box    ",round);
         display(state);
	 
	 state = shift_row(state) ;
	 
	 //print after apply shift_row operation
	 printf("\nround[ %d ].s_row    ",round);
         display(state);
          
	 state = mixcolumn(state) ;
	 	 
	 //print after apply mixcolumn operation
	 printf("\nround[ %d ].m_col    ",round);
         display(state);
          
	 
	 //store round key
	 for(i = 0;i<NB; i++){
             w_temp[i] = w[i+(round*NB)];
         }
         
         //print the key of this round
         printf("\nround[ %d ].k_sch    ",round);
         print_round_key(w_temp);
     
         //xor with round key
	 state = add_round_key(state, w_temp);
	 
	 //print the input of round+1
         printf("\nround[ %d ].start    ",round+1);
         display(state);
     
     } 	 
     
     //final round operations	 
     state = sub_bytes(state);
     
     //print after apply sub_bytes operation
     printf("\nround[10 ].s_box   ");
     display(state);
     
     state = shift_row(state);
     
     //print after apply shift_row operation
     printf("\nround[10 ].s_row    ");
     display(state);
          
	 
     //store final round key
     for(i = 0;i<NB; i++){
         w_temp[i] = w[i+(NR*NB)];
     }
     
     //print the print the key of this round
     printf("\nround[10 ].k_sch    ");
     print_round_key(w_temp);
     
     //cyper text
     state = add_round_key(state, w_temp);
     printf("\nround[10 ].output   ");
     display(state);
  
    //finaly return the cipher text that now store in state
    return state;
}


                        //---End of Encryption---//



                      //---inv_shift_row operation---//                         
unsigned char **inv_shift_row(unsigned char **s) {
    // Allocate memory for row pointer
    unsigned char **shift_result = malloc(NB * sizeof(unsigned char *));
    // Allocate memory for each row
    for (int i = 0; i < NB; i++) {
        shift_result[i] = malloc(NB * sizeof(unsigned char));
    }

    // Shift rows
    shift_result[0] = s[0];  // No shift for the first row
    shift_result[1] = shift_row_one(shift_row_one(shift_row_one(s[1])));
    shift_result[2] = shift_row_one(shift_row_one(s[2]));
    shift_result[3] = shift_row_one(s[3]);
    return shift_result;
}

                        //---End of inv_shift_row---//



                       //---Implementation of inv_sub_bytes---//

                         
//Implementation of s_box function for inv_sub_bytes                        
unsigned char inv_s_box(unsigned char w) {

    /*
    input : a component of word variable.
    x= most significant four bits of input and y = least significant 4-bits .
    output : (x,y)-th element of the s_box matrix.
    */
    unsigned char x = w >> 4; // Extract the 4-most significant bits
    unsigned char y = w & 0x0F; // Extract the 4-least significant bits


    unsigned char inv_s_b[16][16] = {
	    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
	    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
	    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
	    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
	    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
	    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
	    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
	    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
	    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
	    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
	    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
	    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
	    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
	    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
	    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
	    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };
    
    // Return corresponding  S-box value
    return inv_s_b[x][y];
}


 //inv_sub_bytes operation

unsigned char **inv_sub_bytes(unsigned char **s){
    //Allocate memory for row pointer
    unsigned char **inv_sub_result = malloc(NB * sizeof(unsigned char *)) ;
    //Allocate memory for each row
    for(int i=0; i<NB; i++){
        inv_sub_result[i] = malloc(NB * sizeof(unsigned char));
    }
    
    //apply inv_s_box to each byte of the State
    for(int i=0; i<NB; i++){
        for(int j=0; j<NB; j++){
            inv_sub_result[i][j] = inv_s_box(s[i][j]);//inv_s_box on (i,j)-th cell
        }
    }
    
    return inv_sub_result;
    
    } 


                               //---End of inv_sub_bytes---//
                               



                        //---Implemention of inverse mix column opertaion---//
                        
                        
                        
//Implementation of multiplication between two 8-bit number
uint16_t multiplication(uint8_t a, uint8_t b)
{
    uint16_t temp;
    uint16_t result =0x00;
    for (int i = 0;i<8;i++)
    {
        int x= b>>i & 0x01;
        temp = a*x << i;
        result = result ^ temp;
    }
    return result;
}


//Now we Implement reduction function after mulitiplication between two 8-bit number
unsigned char reduction(unsigned char a, unsigned char b){

    unsigned char msb;      // Most significant byte
    unsigned char lsb;      // Least significant byte
    uint16_t result = multiplication(a,b);
    int n=0;
    unsigned char modulo = 0x1b;
    while(n<2){
          
         // Extract the most significant 8 bits
         msb = (unsigned char)(result >> 8);

        // Extract the least significant 8 bits
        lsb = (unsigned char)(result & 0xFF);
        result = multiplication(msb, modulo);
        result = (result ^ lsb );
        n=n+1;
    }
    return result;
    }



//Implementation of inverse mixcolumn
unsigned char **inv_mixcolumn(unsigned char **s){
    //Allocate memory for row pointer
    unsigned char **result = malloc(NB * sizeof(unsigned char *)) ;
    //Allocate memory for each row
    for(int i=0; i<NB; i++){
        result[i] = malloc(NB * sizeof(unsigned char));
    }
    
    unsigned char inv_matrix[4][4] = {{0x0e, 0x0b, 0x0d, 0x09},
    				      {0x09, 0x0e, 0x0b, 0x0d},
    				      {0x0d, 0x09, 0x0e, 0x0b},
    				      {0x0b, 0x0d, 0x09, 0x0e}};
     
    //Allocate memory for row pointer
    unsigned char **sum = malloc(NB * sizeof(unsigned char *)) ;
    //Allocate memory for each row
    for(int i=0; i<NB; i++){
        sum[i] = malloc(NB * sizeof(unsigned char));
    }
          
    
    for(int i=0; i<4; i++){
        for(int j=0; j<4; j++){
            sum[i][j] = 0x00;
            for(int k=0; k<4; k++){
                sum[i][j]  = sum[i][j] ^ reduction(inv_matrix[i][k],s[k][j]);
            }
        }
    }
    return sum;
}

                            //---End inv_mixcolumn---//



                    //---Implementation of decription function---//
              

unsigned char **decryption(unsigned char *buffer,word **w){

    int i,j;
     //convert one-dimension input array into a two dimension state array
     
     //Allocate memory for row pointer
     unsigned char **cipher = malloc(NB * sizeof(unsigned char *)) ;
     //Allocate memory for each row
     for(int i=0; i<NB; i++){
        cipher[i] = malloc(NB * sizeof(unsigned char));
     }   
     //apply convertion rule (i,j) -> i+4*j   
     for(i=0; i<NB; i++){
         for(j=0; j<NB; j++){
             cipher[i][j] = buffer[i+4*j];
         }
     }

      
    //print of cipher text
    printf("\nround[0 ].iinput       ");
    display(cipher);
    unsigned char **mesg = malloc(NB * sizeof(unsigned char *));
    for (int i = 0; i < NB; i++) {
        mesg[i] = malloc(NB * sizeof(unsigned char));
    }

    word **w_temp = (word **)malloc(NB * sizeof(word *));
    for (int i = 0; i < NB; i++) {
        w_temp[i] = w[NR * NB + i];
    }
    //print of round key
    printf("\nround[0 ].ik_sch       ");
    print_round_key(w_temp);
    
    
    mesg = add_round_key(cipher, w_temp);
    
    //input of round-1
    printf("\nround[0 ].istart       "); 
    display(mesg); 
    
     
     for(int round = NR-1; round>=1; round--){
         mesg = inv_shift_row(mesg);
         
         printf("\nround[%d ].is_row       ",NR-round);
         display(mesg);
         
         mesg = inv_sub_bytes(mesg);
         
         printf("\nround[%d ].is_box       ",NR-round);
         display(mesg);
         
         for(int i = 0; i<NB; i++){
             w_temp[i] = w[(round*NB)+i];
         }
         
         printf("\nround[%d ].ik_key       ",NR-round);
         print_round_key(w_temp);
         
         mesg = add_round_key(mesg, w_temp);

         printf("\nround[%d ].ik_add       ",NR-round);
         display(mesg);
         
         mesg = inv_mixcolumn(mesg);
         
         printf("\nround[%d ].is_start     ",NR-round+1);
         display(mesg);
     }
     mesg = inv_shift_row(mesg);
     printf("\nround[10].is_row      ");
     display(mesg);
     
     mesg = inv_sub_bytes(mesg);
     printf("\nround[10].is_box      ");
     display(mesg);
     
     for(int i = 0; i<NB; i++){
             w_temp[i] = w[i];
     }
     
     printf("\nround[10].ik_sch      ");
     print_round_key(w_temp);
     
     mesg = add_round_key(mesg, w_temp);
     
     printf("\nround[10].ioutput      ");
     display(mesg);
     
     return mesg ;
}


   


