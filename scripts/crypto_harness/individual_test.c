#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

struct vectors {
    char testtype[1024];    //DVPT, VADT, VNT, VPT, VTT
    char filename[1024];    //Request File Name
    int ciphertype;  //AES-128,192,256
    int alen, plen, nlen, tlen, count, result;
    unsigned char key[1024]; //
    unsigned char nonce[1024]; //
    unsigned char adata[1024]; //
    unsigned char ciphertext[1024]; //
    unsigned char payload[1024]; //
    struct vectors* next;
};

int vector_process(struct vectors* sentinal);
int vector_decrypt(struct vectors* sentinal);

//Process fax or requests file data into structure
int vector_process(struct vectors* sentinal)
{
/* DVPT128 example
[Alen = 0, Plen = 32, Nlen = 7, Tlen = 4]

Key = 642d893a067856110dfc3954bfb9c991

Count = 60
Nonce = b07f8c6b6896cb
Adata = 00
CT = 5650c75940b117a89b49fd2f40906c49dd5a19febbe5156cbdda9c8279ccd04f20f0ce85
//fax given------
Result = Pass (0)
Payload = 89193ffa308804b42a6d20402bb99031cdac65ec36eb7f59f5d299df2e0b8690
*/
/*
    char * t_testtype = "DVPT"; 
    char * t_filename= "DVPT128"; 
    int t_ciphertype= 128; 
    int t_alen=   0; 
    int t_plen=   32; 
    int t_nlen=   7; 
    int t_tlen=   4; 
    int t_count=  60; 
    unsigned char * t_key= "642d893a067856110dfc3954bfb9c991"; 
    unsigned char * t_nonce= "b07f8c6b6896cb"; 
    unsigned char * t_adata= "00"; 
    unsigned char * t_ciphertext= "5650c75940b117a89b49fd2f40906c49dd5a19febbe5156cbdda9c8279ccd04f20f0ce85"; 
    unsigned char * t_payload= "89193ffa308804b42a6d20402bb99031cdac65ec36eb7f59f5d299df2e0b8690"; 
*/
    /*
 [Alen = 0, Plen = 0, Nlen = 7, Tlen = 16]

Key = 1b0c4d8366defe325174794f895867f2

Count = 15
Nonce = b07f8c6b6896cb
Adata = 00
CT = 9028007b0c5e92faea679f5e2a03beaa
Result = Pass (0)
Payload = 00
*/
    char * t_testtype = "DVPT"; 
    char * t_filename= "DVPT128"; 
    int t_ciphertype= 128; 
    int t_alen=   0; 
    int t_plen=   0; 
    int t_nlen=   7; 
    int t_tlen=   16; 
    int t_count=  15; 
    unsigned char * t_key= "1b0c4d8366defe325174794f895867f2"; 
    unsigned char * t_nonce= "b07f8c6b6896cb"; 
    unsigned char * t_adata= "00"; 
    unsigned char * t_ciphertext= "9028007b0c5e92faea679f5e2a03beaa"; 
    unsigned char * t_payload= "00"; 

    long hex_keylen, hex_noncelen, hex_adatalen, hex_ciphertextlen,hex_payloadlen ;
    unsigned char * h_key;
    unsigned char * h_nonce;
    unsigned char * h_adata;
    unsigned char * h_ciphertext;
    unsigned char * h_payload;
    //Result = Pass (0)
    //Payload = 00
    strncpy(sentinal->testtype,t_testtype,strlen(t_testtype));
    strncpy(sentinal->filename,t_filename,strlen(t_filename));
    sentinal->ciphertype= t_ciphertype;
    sentinal->alen = t_alen;
    sentinal->plen = t_plen;
    sentinal->nlen = t_nlen;
    sentinal->tlen = t_tlen;
    sentinal->count= t_count;
    h_key = OPENSSL_hexstr2buf(t_key, &hex_keylen);
    h_nonce= OPENSSL_hexstr2buf(t_nonce, &hex_noncelen);
    h_adata= OPENSSL_hexstr2buf(t_adata, &hex_adatalen);
    h_ciphertext= OPENSSL_hexstr2buf(t_ciphertext, &hex_ciphertextlen);
    h_payload= OPENSSL_hexstr2buf(t_payload, &hex_payloadlen);

    printf("CipherText Hex Length: %i\n", hex_ciphertextlen);


    strncpy(sentinal->key,h_key,strlen(h_key));
    strncpy(sentinal->nonce,h_nonce,strlen(h_nonce));
    strncpy(sentinal->adata,h_adata,strlen(h_adata));
    strncpy(sentinal->ciphertext,h_ciphertext,strlen(h_ciphertext));
    strncpy(sentinal->payload,h_payload,strlen(h_payload));

    return 0;
}
    
//This will be for VADT, VNT, VPT, VTT tests

//This will be only for DVPT tests
int vector_decrypt(struct vectors* sentinal)
{
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];
    unsigned char tag[1024];
    memset(outbuf,0,1024);
    memset(tag,0,1024);
    EVP_CIPHER_CTX *ctx; 
    ctx = EVP_CIPHER_CTX_new();
    //////////////////////////////////////////////////////////////////
      
    printf("Tag Buffer: %s\n",tag);
    
    int len;
    int plaintext_len;
    int ret;
    int ciphertext_len = strlen(sentinal->ciphertext);
    unsigned char plaintext[1024];
    memset(plaintext,0,1024);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
      printf("Violation");

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
      printf("Violation");

    /* Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sentinal->nlen, NULL))
      printf("Violation");

    printf("Nonce length: %i\n", sentinal->nlen);

    ///////////////GOOOD
    ///////////////GOOOD
    ///////////////GOOOD
    ///////////////GOOOD
    /* Set expected tag value. */
    //if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, sentinal->tlen, NULL))
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, sentinal->tlen, sentinal->ciphertext + sentinal->plen))
      printf("Violation");
    
    printf("Tag Buffer: %s\n",tag);
    printf("Tag length: %i\n", sentinal->tlen);

    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, sentinal->key, sentinal->nonce))
      printf("Violation");
    
    printf("Key Value:\n");
    BIO_dump_fp(stdout, sentinal->key, strlen(sentinal->key));
    printf("Nonce Value:\n");
    BIO_dump_fp(stdout, sentinal->nonce, strlen(sentinal->nonce));

    len = sentinal->plen;


    /* Provide the total ciphertext length 72/2 =36"*/
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, sentinal->plen)) //plen
      printf("Violation");

    printf("CipherText Len: %i\n", ciphertext_len);

    /* Provide any AAD data. This can be called zero or more times as required */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, sentinal->adata, sentinal->alen))
      printf("Violation");
    printf("Adata Value:\n");
    BIO_dump_fp(stdout, sentinal->adata, strlen(sentinal->adata));
    printf("ALen: %i\n", sentinal->alen);
   
    printf("Cipher Text\n");
    BIO_dump_fp(stdout,sentinal->ciphertext, ciphertext_len);
    printf("Cipher End\n");

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, sentinal->ciphertext, sentinal->plen);

    plaintext_len = len;
      
    printf("plain text len: %i\n",sentinal->plen);
    printf("Plain Text\n");
    BIO_dump_fp(stdout, plaintext, sentinal->plen);
    printf("Plain Text End\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
      printf("*********************");
      printf("\nPayload Matches\n");
      printf("*********************\n");
        BIO_dump_fp(stdout, plaintext, len);
        return plaintext_len;
    } else {
      printf("*********************");
      printf("\n Payload Fail \n");
      printf("*********************\n");
        /* Verify failed */
        return -1;
    }


    return 0;
}


int main(int argc, char *argv[]) 
{
    struct vectors* head = NULL;
    struct vectors* sentinal= NULL;
    struct vectors* playback= NULL;

    head = (struct vectors*)malloc(sizeof(struct vectors));
    sentinal = head;

    vector_process(sentinal);
    vector_decrypt(sentinal);
}
