#include <stdint.h>
extern int NB;
extern int NR;

// Define the word structure
typedef struct {
    unsigned char w0;
    unsigned char w1;
    unsigned char w2;
    unsigned char w3;
} word;

void print_round_key(word **);
void print_key_schedule(word **);
void display(unsigned char **);
word *rotword(word *);
unsigned char s_box(unsigned char );
word *subword(word *);
word *round_cons(int );
word *xor_of_words(word *, word *);
word **key_expansion(unsigned char key[16]);
unsigned char *shift_row_one(unsigned char *);
unsigned char **shift_row(unsigned char **);
unsigned char x_time(unsigned char );
unsigned char multi_3(unsigned char );
unsigned char **mixcolumn(unsigned char **);
unsigned char **sub_bytes(unsigned char **);
unsigned char **add_round_key(unsigned char **, word **);
unsigned char **encryption(unsigned char *, word ** );
unsigned char **inv_shift_row(unsigned char **);
unsigned char inv_s_box(unsigned char );
unsigned char **inv_sub_bytes(unsigned char **);
uint16_t multiplication(uint8_t , uint8_t );
unsigned char reduction(unsigned char , unsigned char );
unsigned char **inv_mixcolumn(unsigned char **);
unsigned char **decryption(unsigned char *,word **);




