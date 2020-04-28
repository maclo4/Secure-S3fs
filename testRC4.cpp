// #define _LARGEFILE_SOURCE
// #define _FILE_OFFSET_BITS 64
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
//#include <iterator>
#include <cstdlib>
#include <iostream>
//#include </home/maclo4/Documents/openssl/openssl/crypto>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#define EVP_MAX_KEY_LENGTH 64

//#include <rc4_enc.c>
//#include <openssl/rc4.h>

typedef struct rc4_key_st {
    RC4_INT x, y;
    RC4_INT data[256];
} RC4_KEY;


int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                   const unsigned char *salt, const unsigned char *data,
                   int datal, int count, unsigned char *key,
                   unsigned char *iv)
{
    EVP_MD_CTX *c;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    int niv, nkey, addmd = 0;
    unsigned int mds = 0, i;
    int rv = 0;
    nkey = EVP_CIPHER_key_length(type);
    niv = EVP_CIPHER_iv_length(type);
    OPENSSL_assert(nkey <= EVP_MAX_KEY_LENGTH);
    OPENSSL_assert(niv <= EVP_MAX_IV_LENGTH);

    if (data == NULL)
        return nkey;

    c = EVP_MD_CTX_new();
    if (c == NULL)
        goto err;
    for (;;) {
        if (!EVP_DigestInit_ex(c, md, NULL))
            goto err;
        if (addmd++)
            if (!EVP_DigestUpdate(c, &(md_buf[0]), mds))
                goto err;
        if (!EVP_DigestUpdate(c, data, datal))
            goto err;
        if (salt != NULL)
            if (!EVP_DigestUpdate(c, salt, PKCS5_SALT_LEN))
                goto err;
        if (!EVP_DigestFinal_ex(c, &(md_buf[0]), &mds))
            goto err;

        for (i = 1; i < (unsigned int)count; i++) {
            if (!EVP_DigestInit_ex(c, md, NULL))
                goto err;
            if (!EVP_DigestUpdate(c, &(md_buf[0]), mds))
                goto err;
            if (!EVP_DigestFinal_ex(c, &(md_buf[0]), &mds))
                goto err;
        }
        i = 0;
        if (nkey) {
            for (;;) {
                if (nkey == 0)
                    break;
                if (i == mds)
                    break;
                if (key != NULL)
                    *(key++) = md_buf[i];
                nkey--;
                i++;
            }
        }
        if (niv && (i != mds)) {
            for (;;) {
                if (niv == 0)
                    break;
                if (i == mds)
                    break;
                if (iv != NULL)
                    *(iv++) = md_buf[i];
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0))
            break;
    }
    rv = EVP_CIPHER_key_length(type);
 err:
    EVP_MD_CTX_free(c);
    OPENSSL_cleanse(md_buf, sizeof(md_buf));
    return rv;
}

void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data)
{
    register RC4_INT tmp;
    register int id1, id2;
    register RC4_INT *d;
    unsigned int i;

    d = &(key->data[0]);
    key->x = 0;
    key->y = 0;
    id1 = id2 = 0;

#define SK_LOOP(d,n) { \
                tmp=d[(n)]; \
                id2 = (data[id1] + tmp + id2) & 0xff; \
                if (++id1 == len) id1=0; \
                d[(n)]=d[id2]; \
                d[id2]=tmp; }

    for (i = 0; i < 256; i++)
        d[i] = i;
    for (i = 0; i < 256; i += 4) {
        SK_LOOP(d, i + 0);
        SK_LOOP(d, i + 1);
        SK_LOOP(d, i + 2);
        SK_LOOP(d, i + 3);
    }
}

void RC4(RC4_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata)
{
    register RC4_INT *d;
    register RC4_INT x, y, tx, ty;
    size_t i;

    x = key->x;
    y = key->y;
    d = key->data;

#define LOOP(in,out) \
                x=((x+1)&0xff); \
                tx=d[x]; \
                y=(tx+y)&0xff; \
                d[x]=ty=d[y]; \
                d[y]=tx; \
                (out) = d[(tx+ty)&0xff]^ (in);

    i = len >> 3;
    if (i) {
        for (;;) {
            LOOP(indata[0], outdata[0]);
            LOOP(indata[1], outdata[1]);
            LOOP(indata[2], outdata[2]);
            LOOP(indata[3], outdata[3]);
            LOOP(indata[4], outdata[4]);
            LOOP(indata[5], outdata[5]);
            LOOP(indata[6], outdata[6]);
            LOOP(indata[7], outdata[7]);
            indata += 8;
            outdata += 8;
            if (--i == 0)
                break;
        }
    }
    i = len & 0x07;
    if (i) {
        for (;;) {
            LOOP(indata[0], outdata[0]);
            if (--i == 0)
                break;
            LOOP(indata[1], outdata[1]);
            if (--i == 0)
                break;
            LOOP(indata[2], outdata[2]);
            if (--i == 0)
                break;
            LOOP(indata[3], outdata[3]);
            if (--i == 0)
                break;
            LOOP(indata[4], outdata[4]);
            if (--i == 0)
                break;
            LOOP(indata[5], outdata[5]);
            if (--i == 0)
                break;
            LOOP(indata[6], outdata[6]);
            if (--i == 0)
                break;
        }
    }
    key->x = x;
    key->y = y;
}



/*

void parseargs(int argc, char ** argv, std::string & key, std::string & file, bool & hex)
{
	bool readkey = false ;
	bool readfile = false;
	bool toomanyargs =false;

	printf("argc: %d", argc);

	for( int i=1 ; i<argc ; i++ )
	{
		std::string arg = argv[i];
		if(arg=="-h")
		{
			hex=true;
		}
		else if(!readkey)
		{
			key=arg;
			readkey=true;
		}
		else if(!readfile)
		{
			file=arg;
			readfile=true;
		}
		else
		{
			toomanyargs=true;
		}
	}

	if(toomanyargs || !readfile || !readkey)
	{
		std::cout << "Usage is: " << argv[0] << " [-h] key file" << std::endl;
		exit(EXIT_FAILURE);
	}

	return;
}

*/ 
int parseargs(int argc, char *argv[], int length){
	int fd;
	//int length;

	if(argc != 3){
		printf("format: ./testRC4 filename key \n");
		exit(0);
	}
	
	if((fd = open(argv[1], O_RDONLY)) == -1){
		perror("failed to open file\n");
		exit(0);
	}
	
	if((length = lseek(fd, 0, SEEK_END)) == -1){
		perror("failed to find end of file");
		exit(0);
	}

	if(lseek(fd, 0, SEEK_SET) == -1){
		perror("failed to find start of file");
		exit(0);
	}
	
	return fd;
	

	//return normalInput;
	}

int main(int argc, char *argv[])
{
	RC4_KEY key;
	size_t len;
	//const unsigned char keyString[] = "Key"; // should be const
	//const unsigned char indata[] = "Plaintext"; // should be const unsigned
	unsigned char hexKey[EVP_MAX_KEY_LENGTH];
	int fd;
	int fd2;
	unsigned long length;
    FILE *doge;
    unsigned char *buffer;

	if(argc != 3){
		printf("Must pass file by argument \n");
		exit(0);
	}

/*
	unsigned long fileLen;

        //Open file
        file = fopen(argv[1], "rb");
        if (!file)
        {
                fprintf(stderr, "Unable to open file %s", argv[1]);
                return;
        }

        //Get file length
        fseek(file, 0, SEEK_END);
        fileLen=ftell(file);
        fseek(file, 0, SEEK_SET);

        //Allocate memory
        buffer=(char *)malloc(fileLen);
        if (!buffer)
        {
                fprintf(stderr, "Memory error!");
                                fclose(file);
                return 1;
        }

       fread(buffer,fileLen,sizeof(unsigned char),file);
       fclose(file);


*/

	if((fd = open(argv[1], O_RDONLY)) == -1){
		perror("failed to open file\n");
		exit(0);
	}
    


	if((length = lseek(fd, 0, SEEK_END)) == -1){
		perror("failed to find end of file");
		exit(0);
	}
  
  

	if(lseek(fd, 0, SEEK_SET) == -1){
		perror("failed to find start of file");
		exit(0);
	}
	
	
	unsigned char *indata = (unsigned char*)malloc(sizeof(char) * length);
   // printf("length: %d \n", length);
	if(read(fd, indata, length) == -1){
		perror("failed to read file");
		exit(0);
	}
   
	unsigned char *keyString = argv[2];

  //std::cout << "file name string: " << argv[1] << std::endl;
 // std::cout << "key: " << keyString << " " << argv[2] << " ." << std::endl;
	

	// get length of string for evp_bytestokey
    int str_len = strlen(keyString);

    //just printing it for myself to see
    //printf("stre_len: %d \n", str_len);

    // make sure hexKey is cleared then call evpbytes
    memset(hexKey, 0, sizeof(hexKey));
   int KeyByteLen = EVP_BytesToKey(EVP_rc4(),EVP_sha256(),NULL,(unsigned char *)keyString,str_len, 1, hexKey , NULL);

/*
   // print out the data in hexKey
	printf("strlen(hexKey): %d \n hexKey: ", (int)strlen((const char*) hexKey));
   for(int i =0; i < strlen((const char*)hexKey); i++){
   		 printf("%X " , hexKey[i]);
   }
  	printf("\n");
*/

   	// set the key value
    RC4_set_key(&key, KeyByteLen, hexKey); //key struct, length, key

    // print the value of key
    //printf("size of key.data %lu \n content of key.data \n", sizeof(key.data));
    /*
    for(int i = 0; i<256; i++){
 	   printf("%X, ", key.data[i]);
	}
*/

   	// set size to the length of the file
    int size = strlen((const char*) indata);

    /*print the data of the file in hex just to see
	printf("\n\n indata: ");
	    for(int i = 0; i<size; i++){
	 	   printf("%X, ", indata[i]);
		}
*/
	// allocate space for outdata based on the size of the indata string
    unsigned char *outdata = (unsigned char*)calloc(size, sizeof(unsigned char));
    memset(outdata, 0, sizeof(outdata));

/*
    // print out info for myself to see
    printf("\nsizeof indata: %d \n", sizeof(indata));
    printf("sizeof outdata: %d \n", sizeof(outdata));
*/


    //finally call rc4 to encrypt the file and output to outdata
    RC4(&key, size, indata, outdata); // key struct, length, indata, outdata

    //print your encrypted data
    //printf("\n indata: %s\n  outdata: %X\n   strlen outdata: %d \n", indata, outdata, strlen((const char*) outdata));
    
    size = strlen((const char*)outdata);
/*
	 std::cout << "outdata (real): ";
     for(int i = 0; i<size; i++){
 	   	printf("%X, ", outdata[i]);
		}
	std::cout << "\n";
*/



    
	//printf("\n ------------------------------------------------------- \n");

	std::string file = argv[1];
	//int fd2 = open(file.c_str(), O_RDONLY);
	
	if(file.find(".rc4", file.length()-4) != std::string::npos) //ie, if file ends with ".rc4"
	{
		file.erase(file.length()-4);
	}
	else
	{
		file.append(".rc4");
	}

	
	std::fstream outfile;
	outfile.open(file.c_str(), std::ios::in);

	/*if(outfile.is_open()) //file we are going to write to exists!
	{
		std::cout << file << " already exists, aborting to preserve it" << std::endl;
		exit(EXIT_FAILURE);
	}*/

	outfile.close();
	outfile.open(file.c_str(), std::ios::out | std::ios::binary);
	if(outfile.is_open()){

		outfile << outdata;
	}

	

 //std::cout << "fd: " << fd << "  fd2: " <<  std::endl;


}
