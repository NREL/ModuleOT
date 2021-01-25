#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <dirent.h>


struct vectors {
    unsigned int testnumber;      //Which test number are we working with  (i.e. 0 - all the leidos vectors)
    char testtype[1024];
    unsigned int vectortest;      //0: Req 1:Fax
    char filename[1024];
    //char ciphertype[1024];
    int ciphertype;
    unsigned char key[1024];
    unsigned char mct_fax_key[1024];
    int keylen;
    int mct_fax_keylen;
    char op[1024];
    unsigned char pt[1024];
    unsigned char mct_fax_pt[1024];
    int ptlen;
    int mct_fax_ptlen;
    unsigned char ct[1024];
    unsigned char mct_fax_ct[1024];
    int ctlen;
    int mct_fax_ctlen;
    unsigned char result[1024];
    unsigned char ciphreport[1024];
    int pass; //Vector failed
    int resultlen;
    int vcount; //Vector Count in File
    struct vectors* next;
};

struct vectors*  mct_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest);
struct vectors*  vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest);
int process_mct(struct vectors* list);
int process(struct vectors* list);
int vector_write(struct vectors* list);

int vector_write(struct vectors* playback)
{
    //Write out CAVP Report
    //
    //
    char writeout[1024];
    char scratch[1024];
    memset(scratch,0,1024);
    char  aes_resp_dir[]= "./Leidos_Vectors/AES/resp/";
    time_t now;
    char * header1_fmt = "# CAVS 21.4\n";
    char * header2_fmt = "# Config info for nrel-openssl-sample\n";
    char * header3_fmt = "# AESVS ";
    char * header4_fmt = "# State : Encrypt\n";
    char * header5_fmt = "# Key Length : ";
    char * header6_fmt = "# Generated on ";
    char * operation_fmt ="[ENCRYPT]\n";
    char * count_fmt="COUNT = ";
    char * key_fmt="KEY = ";
    char * pt_fmt="PLAINTEXT = ";
    char * ct_fmt="CIPHERTEXT = ";
    char * fail_fmt="########FAILED CIPHERTEXT########";
    char * break_fmt="\n";
    FILE * ResponseFile;
    int newfile; 
    while(playback->next!= NULL)
    {
        printf(">>FILE: %s Count: %i \n",playback->filename, playback->vcount);
        if(playback->vcount == 0)
        {
            //printf("%s \n", playback->filename);
            memset(writeout,0,1024);
            memset(scratch,0,1024);
            sprintf(writeout,"%s%s%i.rsp", aes_resp_dir,playback->filename,playback->ciphertype);
            //ResponseFile = fopen(playback->filename, "w");
            ResponseFile = fopen(writeout, "w");
            fwrite(header1_fmt, 1,strlen(header1_fmt), ResponseFile);
            fwrite(header2_fmt, 1,strlen(header2_fmt), ResponseFile);
            fwrite(header3_fmt, 1,strlen(header3_fmt), ResponseFile);

            fwrite(playback->testtype, 1,strlen(playback->testtype)-3, ResponseFile);
            fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);

            fwrite(header4_fmt, 1,strlen(header4_fmt), ResponseFile);
            //fwrite(header5_fmt, 1,strlen(header5_fmt), ResponseFile);
            sprintf(scratch,"%s%i",header5_fmt,playback->ciphertype);
            fwrite(scratch,1,strlen(scratch),ResponseFile);
            //fwrite(playback->ciphertype, 1,strlen(playback->ciphertype), ResponseFile);
            fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);

            time(&now);
            fwrite(header6_fmt, 1,strlen(header6_fmt), ResponseFile);
            fprintf(ResponseFile, "%s\n", ctime(&now));

            fwrite(operation_fmt, 1,strlen(operation_fmt), ResponseFile);
        }
        //while(playback->next->vcount != 0)

        //Vector Count
        fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
        fwrite(count_fmt, 1,strlen(count_fmt), ResponseFile);
        fprintf(ResponseFile, "%i", playback->vcount);

        //Key Text
        fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
        fwrite(key_fmt, 1,strlen(key_fmt), ResponseFile);
        fwrite(playback->key, 1,playback->keylen, ResponseFile);
        //fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);

        //Plain Text
        fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
        fwrite(pt_fmt, 1,strlen(pt_fmt), ResponseFile);
        fwrite(playback->pt, 1,playback->ptlen, ResponseFile);
        //fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);


        //Cipher Text
        //fwrite(playback->pt, 1,playback->ptlen, ResponseFile);
        //fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);


        //Cipher Text
        fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
        if(playback->pass == 0)
        {
            fwrite(fail_fmt, 1,strlen(fail_fmt), ResponseFile);
        }
        else
        {
            fwrite(ct_fmt, 1,strlen(ct_fmt), ResponseFile);
            //fwrite(playback->ct, 1,playback->ctlen, ResponseFile);
            fwrite(playback->ct, 1,strlen(playback->ct), ResponseFile);
        }
        fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
        //fwrite(playback->pt, 1,sizeof(playback->pt), ResponseFile);
        playback = playback->next;

    }

    return 0;
}

struct vectors*  mct_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest)
{
    char filestream[1024]; //File buffer
    char *data; //Buffer 
    int dlen, vtt_p_alen, vtt_p_plen, vtt_p_nlen, vtt_p_tlen;
    char vpt_key[1024];
    char vpt_nonce[1024];
    int linenum = 0;
    int curr_testnumber= sentinal->testnumber; //grab the current test number
    
    if(sentinal->next!=NULL)
    {
        printf("Bad Book Keeping");
        exit(-1);
    }
    
    while(fgets(filestream, sizeof(filestream), vparse))
    {
        //printf("cipherbits %i\n",ciphersize);
        if(strncmp(filestream, "COUNT =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->vcount = atoi(data);
            sentinal->ciphertype = ciphersize;
            //printf("Test Number = %i\n", sentinal->testnumber);
            //printf("Count = %i\n", sentinal->vcount);
        }
            if (strncmp(filestream, "KEY =",5)==0)
            {
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                if(sentinal->vcount == 0)
                {
                    strncpy(sentinal->key, data, strlen(data)-2);
                    sentinal->keylen = strlen(sentinal->key);
                }
                    strncpy(sentinal->mct_fax_key, data, strlen(data)-2);
                    sentinal->mct_fax_keylen = strlen(sentinal->mct_fax_key);
                //printf("Key = %s\n", sentinal->key);
            }
            if(strncmp(filestream, "PLAINTEXT =",11)==0)
            {
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                if(sentinal->vcount == 0)
                {
                    strncpy(sentinal->pt, data, strlen(data)-2);
                    sentinal->ptlen= strlen(sentinal->pt);
                }
                    strncpy(sentinal->mct_fax_pt, data, strlen(data)-2);
                    sentinal->mct_fax_ptlen= strlen(sentinal->mct_fax_pt);
                //printf("Plaintext = %s\n", sentinal->pt);
                if(vectortest == 0)
                {
                    //printf("This is a REQ file\n");
                    sentinal->vectortest = vectortest; //tell us if fax or req
                    strncpy(sentinal->testtype,fname,strlen(fname));
                    strncpy(sentinal->filename,fname,strlen(fname));

                    //increment and go to next one
                    sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                    sentinal = sentinal->next;

                    //We are on a new record

                    //Monte Carlo requires 100, so lets create 100 blank ones with test numbers, types, and ciphers
                    for(int mct_count = 1; mct_count < 100; mct_count++)
                    {
                        sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                        curr_testnumber +=1;
                        sentinal->vectortest = vectortest; //tell us if fax or req
                        sentinal->ciphertype = ciphersize;
                        strncpy(sentinal->testtype,fname,strlen(fname));
                        strncpy(sentinal->filename,fname,strlen(fname));
                        sentinal->testnumber = curr_testnumber;
                        sentinal->vcount = mct_count;
                        
                        sentinal = sentinal->next;

                    }
                    sentinal->next= NULL; //set the nullbit
                    curr_testnumber +=1;
                    sentinal->testnumber = curr_testnumber;
                }
            }
		
            if(strncmp(filestream, "CIPHERTEXT =",12)==0 && (vectortest == 1))
            {
                //printf("This is a FAX file\n");
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                strncpy(sentinal->mct_fax_ct, data, strlen(data)-2);
                sentinal->mct_fax_ctlen= strlen(sentinal->mct_fax_ct);
                sentinal->vectortest = vectortest; //tell us if fax or req
                //printf("Ciphertext = %s\n", sentinal->ct);
                strncpy(sentinal->testtype,fname,strlen(fname));
                strncpy(sentinal->filename,fname,strlen(fname));

                //increment and go to next one
                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }

    }
    return sentinal;

}
struct vectors*  vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest)
{
    char filestream[1024]; //File buffer
    char *data; //Buffer 
    int dlen, vtt_p_alen, vtt_p_plen, vtt_p_nlen, vtt_p_tlen;
    char vpt_key[1024];
    char vpt_nonce[1024];
    int linenum = 0;
    int curr_testnumber= sentinal->testnumber; //grab the current test number
    
    if(sentinal->next!=NULL)
    {
        printf("Bad Book Keeping");
        exit(-1);
    }
    
    while(fgets(filestream, sizeof(filestream), vparse))
    {
        //printf("cipherbits %i\n",ciphersize);
        if(strncmp(filestream, "COUNT =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->vcount = atoi(data);
            sentinal->ciphertype = ciphersize;
            //printf("Test Number = %i\n", sentinal->testnumber);
            //printf("Count = %i\n", sentinal->vcount);
        }
            if (strncmp(filestream, "KEY =",5)==0)
            {
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                strncpy(sentinal->key, data, strlen(data)-2);
                sentinal->keylen = strlen(sentinal->key);
                //printf("Key = %s\n", sentinal->key);
            }
            if(strncmp(filestream, "PLAINTEXT =",11)==0)
            {
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                strncpy(sentinal->pt, data, strlen(data)-2);
                sentinal->ptlen= strlen(sentinal->pt);
                //printf("Plaintext = %s\n", sentinal->pt);
                if(vectortest == 0)
                {
                    //printf("This is a REQ file\n");
                    sentinal->vectortest = vectortest; //tell us if fax or req
                    strncpy(sentinal->testtype,fname,strlen(fname));
                    strncpy(sentinal->filename,fname,strlen(fname));

                    //increment and go to next one
                    sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                    sentinal = sentinal->next;
                    sentinal->next= NULL; //set the nullbit
                    curr_testnumber +=1;
                    sentinal->testnumber = curr_testnumber;

                }
            }
		
            if(strncmp(filestream, "CIPHERTEXT =",12)==0 && (vectortest == 1))
            {
                //printf("This is a FAX file\n");
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                strncpy(sentinal->ct, data, strlen(data)-2);
                sentinal->ctlen= strlen(sentinal->ct);
                sentinal->vectortest = vectortest; //tell us if fax or req
                //printf("Ciphertext = %s\n", sentinal->ct);
                strncpy(sentinal->testtype,fname,strlen(fname));
                strncpy(sentinal->filename,fname,strlen(fname));
               
                //increment and go to next one
                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }

    }
    return sentinal;

}
int process_mct(struct vectors* list)
{
    char * goat;
    char * zgoat;
    int zbits = list->ciphertype;

    unsigned char next_hex_key[1024]; //hexstr2buf
    memset(next_hex_key,0,1024);

    unsigned char *hex_key; //hexstr2buf
    long hex_keylen;

    unsigned char *hex_plaintext;
    long hex_ptlen;

    unsigned char *ptprev;
    long hex_ptprevlen;

    unsigned char *hex_ciphertext;
    long hex_ctlen;

    unsigned char ciphertext[1024];
    int len, tmplen;
    FILE *out; 

    //hex literal and convert to binary buffer
    hex_key = OPENSSL_hexstr2buf(list->key, &hex_keylen);
    hex_plaintext = OPENSSL_hexstr2buf(list->pt, &hex_ptlen);
    ptprev        = OPENSSL_hexstr2buf(list->pt, &hex_ptprevlen);

    if(list->vectortest == 1) //we only have the ct if doing a fax
        hex_ciphertext= OPENSSL_hexstr2buf(list->ct, &hex_ctlen);

    EVP_CIPHER_CTX *ctx; 
    ctx = EVP_CIPHER_CTX_new();

    switch(zbits)
    {
        case 128:
            EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hex_key, NULL);
            break;
        case 192:
            EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, hex_key, NULL);
            break;
        case 256:
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, hex_key, NULL);
            break;
    }

    EVP_CIPHER_CTX_set_padding(ctx,0);
    unsigned char hex_prev_ct[1024];
    memset(hex_prev_ct,0,1024);

    for(int mct_rounds=0; mct_rounds < 1000; mct_rounds++)
    {
        EVP_EncryptUpdate(ctx, ciphertext, &len, hex_plaintext, hex_ptlen);
        memcpy(hex_plaintext, ciphertext,len);
       
        if(mct_rounds == 998)
        {
            printf("C[J+1]\n");
            BIO_dump_fp(stdout, ciphertext, 24);

            for(int gato = 0; gato < len; gato++)
            {
                hex_prev_ct[gato] = ciphertext[gato];
            }
        }
        
    }

    EVP_EncryptFinal_ex(ctx, ciphertext + len,&tmplen);
    len+=tmplen;
    EVP_CIPHER_CTX_free(ctx);
    BIO_dump_fp(stdout, hex_prev_ct, 24);

    
    goat = OPENSSL_buf2hexstr(ciphertext, len);
    strncpy(list->result,ciphertext,len);
    
    char ct_final[1024];
    memset(ct_final,0,1024);

        int i = 0;
        int kay = 0;
        while(goat[i] != NULL)
        {
            //if(strrchr(ct_final[i],':'
            if(goat[i]!=':')
            {
                ct_final[kay] = tolower(goat[i]);
                //printf("%c", tolower(goat[i]));
                kay++;
            }
            i++;

        }

    strncpy(list->ct, ct_final, strlen(ct_final));
//
    if(list->vectortest == 1)
    {
        if(strncmp(list->mct_fax_ct,list->ct,strlen(list->ct)) == 0)
        {
            list->pass = 1;
            printf("Count %i\nPASS FAX CIPHERTEXT: %s\n", list->vcount, list->ct);

        }

    }

   if(list->next != NULL && (strncmp(list->next->testtype, "ECBMCT", 6) == 0))
   {
       char next_hex_key_final[1024];
       memset(next_hex_key_final,0,1024);
       switch(zbits)
       {
           case 128:

               //Next key for 128  = Key xor CT 
               for(int hkeybits128 = 0; hkeybits128 < len; hkeybits128++)
               {
                   next_hex_key[hkeybits128] = hex_key[hkeybits128] ^ ciphertext[hkeybits128];
               }
               zgoat = OPENSSL_buf2hexstr(next_hex_key, len);

               int i = 0;
               int kay = 0;
               while(zgoat[i] != NULL)
               {
                   if(zgoat[i]!=':')
                   {
                       next_hex_key_final[kay] = tolower(zgoat[i]);
                       kay++;
                   }
                   i++;

               }

               //we've done 100 values don't set the next one  
               if(list->vcount != 99) 
               {
                   printf("Next ascii key is: %s\n", next_hex_key_final);
                   strncpy(list->next->key,next_hex_key_final,strlen(next_hex_key_final));
                   list->next->keylen = strlen(next_hex_key_final);


                   //PT[J+1] = CT [J]
                   strncpy(list->next->pt,ct_final,strlen(ct_final));
                   printf("Next pt is: %s\n", list->next->pt);
                   list->next->ptlen = strlen(ct_final);
               }

               //If it's a fax file lets compare the PT, CT, and keys
               //unsigned char mct_fax_key[1024];

               if(list->vectortest == 1)
               {
                   if(strncmp(list->mct_fax_key, list->key, strlen(list->mct_fax_key)) == 0)
                   {
                       printf("Fax Key PASS\n");
                       list->pass = 1;
                   }
                   else
                   {
                       printf("Fax Key FAIL\n");
                       list->pass = 0;
                   }

                   if(strncmp(list->mct_fax_pt, list->pt, strlen(list->mct_fax_pt)) == 0)
                   {  
                       printf("Fax Plaintext PASS\n");
                       list->pass = 1;
                   }
                   else
                   {
                       printf("Fax Key FAIL\n");
                       list->pass = 0;
                   }
               }
                  if(list->vectortest == 0)
                  {
                       list->pass = 1;
                  }

                  if(list->vectortest == 0 && list->vcount == 98)
                  {
                       list->next->pass = 1;
                  }
               break;
           case 192:

               memset(next_hex_key_final,0,1024);

               for(int hkeybits192 = 0; hkeybits192 < 24; hkeybits192++)
               {
                   if(hkeybits192 < 8)
                   {
                       next_hex_key[hkeybits192] = hex_key[hkeybits192] ^ hex_prev_ct[hkeybits192+8];
                       printf("\n[%x] XOR [%x] = ", hex_key[hkeybits192], hex_prev_ct[hkeybits192+8]);
                       printf("[%x]", next_hex_key[hkeybits192]);
                   }
                   else
                   {
                       next_hex_key[hkeybits192] = hex_key[hkeybits192] ^ ciphertext[hkeybits192 - 8];
                       printf("\n[%x] XOR [%x] = ", hex_key[hkeybits192], ciphertext[hkeybits192 - 8]);
                       printf("[%x]", next_hex_key[hkeybits192]);
                   }
                    
               }
               zgoat = OPENSSL_buf2hexstr(next_hex_key, 24);

               i = 0;
               kay = 0;
               while(zgoat[i] != NULL)
               {
                   if(zgoat[i]!=':')
                   {
                       next_hex_key_final[kay] = tolower(zgoat[i]);
                       kay++;
                   }
                   i++;

               }

               if(list->vcount != 99) 
               {
                   printf("\nNext ascii key is: %s\n", next_hex_key_final);
                   strncpy(list->next->key,next_hex_key_final,strlen(next_hex_key_final));
                   list->next->keylen = strlen(next_hex_key_final);

                   //PT[J+1] = CT [J]
                   strncpy(list->next->pt,ct_final,strlen(ct_final));
                   printf("Next pt is: %s\n", list->next->pt);
                   list->next->ptlen = strlen(ct_final);
               }


               printf("The key generated: \n");
               BIO_dump_fp(stdout, next_hex_key, 24);
               if(list->vectortest == 1)
               {
                   if(strncmp(list->mct_fax_key, list->key, strlen(list->mct_fax_key)) == 0)
                   {
                       printf("Fax Key PASS\n");
                       list->pass = 1;
                   }
                   else
                   {
                       printf("Fax Key FAIL\n");
                       list->pass = 0;
                   }

                   if(strncmp(list->mct_fax_pt, list->pt, strlen(list->mct_fax_pt)) == 0)
                   {  
                       printf("Fax Plaintext PASS\n");
                       list->pass = 1;
                   }
                   else
                   {
                       printf("Fax Key FAIL\n");
                       list->pass = 0;
                   }
               }
                  if(list->vectortest == 0)
                  {
                       list->pass = 1;
                  }
                  if(list->vectortest == 0 && list->vcount == 98)
                  {
                       list->next->pass = 1;
                  }
               break;
           
           case 256:
               memset(next_hex_key_final,0,1024);

               for(int hkeybits256 = 0; hkeybits256 < 32; hkeybits256++)
               {
                   if(hkeybits256 < 16)
                   {
                       next_hex_key[hkeybits256] = hex_key[hkeybits256] ^ hex_prev_ct[hkeybits256];
                       printf("\n[%x] XOR [%x] = ", hex_key[hkeybits256], hex_prev_ct[hkeybits256]);
                       printf("[%x]", next_hex_key[hkeybits256]);
                   }
                   else
                   {
                       next_hex_key[hkeybits256] = hex_key[hkeybits256] ^ ciphertext[hkeybits256 - 16];
                       printf("\n[%x] XOR [%x] = ", hex_key[hkeybits256], ciphertext[hkeybits256 - 16]);
                       printf("[%x]", next_hex_key[hkeybits256]);
                   }
                    
               }
               zgoat = OPENSSL_buf2hexstr(next_hex_key, 32);

               i = 0;
               kay = 0;
               while(zgoat[i] != NULL)
               {
                   if(zgoat[i]!=':')
                   {
                       next_hex_key_final[kay] = tolower(zgoat[i]);
                       kay++;
                   }
                   i++;

               }

               if(list->vcount != 99) 
               {
                   printf("\nNext ascii key is: %s\n", next_hex_key_final);
                   strncpy(list->next->key,next_hex_key_final,strlen(next_hex_key_final));
                   list->next->keylen = strlen(next_hex_key_final);

                   //PT[J+1] = CT [J]
                   strncpy(list->next->pt,ct_final,strlen(ct_final));
                   printf("Next pt is: %s\n", list->next->pt);
                   list->next->ptlen = strlen(ct_final);
                   
               }

               printf("The key generated: \n");
               BIO_dump_fp(stdout, next_hex_key, 32);
               
               if(list->vectortest == 1)
               {
                   if(strncmp(list->mct_fax_key, list->key, strlen(list->mct_fax_key)) == 0)
                   {
                       printf("Fax Key PASS\n");
                       list->pass = 1;
                   }
                   else
                   {
                       printf("Fax Key FAIL\n");
                       list->pass = 0;
                   }

                   if(strncmp(list->mct_fax_pt, list->pt, strlen(list->mct_fax_pt)) == 0)
                   {  
                       printf("Fax Plaintext PASS\n");
                       list->pass = 1;
                   }
                   else
                   {
                       printf("Fax Key FAIL\n");
                       list->pass = 0;
                   }
               }
                  if(list->vectortest == 0)
                  {
                       list->pass = 1;
                  }
                  if(list->vectortest == 0 && list->vcount == 98)
                  {
                       list->next->pass = 1;
                  }

               break;
       }
   }


    return 0;
}
int process(struct vectors* list)
{
    /*printf("File->%s\n", list->testtype);
      printf("Cipher->AES-%s-ECB\n", list->ciphertype);
      printf("Key->%s\n", list->key);
      printf("KeyLen->%i\n", list->keylen);
      printf("Plaintext->%s\n", list->pt);
      printf("Plaintext Len->%i\n", list->ptlen);
      printf("Ciphertext->%s\n", list->ct);
      printf("Ciphertext Len->%i\n", list->ctlen);*/

    char * goat;

    //int zbits = atoi(list->ciphertype);
    int zbits = list->ciphertype;

    unsigned char *hex_key; //hexstr2buf
    long hex_keylen;

    unsigned char *hex_plaintext;
    long hex_ptlen;

    unsigned char *hex_ciphertext;
    long hex_ctlen;


    unsigned char ciphertext[1024];
    int len, tmplen;
    FILE *out; 

    //hex literal and convert to binary buffer
    hex_key = OPENSSL_hexstr2buf(list->key, &hex_keylen);
    hex_plaintext = OPENSSL_hexstr2buf(list->pt, &hex_ptlen);
    
    if(list->vectortest == 1) //we only have the ct if doing a fax
    hex_ciphertext= OPENSSL_hexstr2buf(list->ct, &hex_ctlen);


    EVP_CIPHER_CTX *ctx; 
    ctx = EVP_CIPHER_CTX_new();

    switch(zbits)
    {
        case 128:
            EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hex_key, NULL);
            break;
        case 192:
            EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, hex_key, NULL);
            break;
        case 256:
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, hex_key, NULL);
            break;
    }


    EVP_CIPHER_CTX_set_padding(ctx,0);
    
    EVP_EncryptUpdate(ctx, ciphertext, &len, hex_plaintext, hex_ptlen);




    EVP_EncryptFinal_ex(ctx, ciphertext + len,&tmplen);
    len+=tmplen;


    EVP_CIPHER_CTX_free(ctx);


    goat = OPENSSL_buf2hexstr(ciphertext, len);

    strncpy(list->result,ciphertext,len);

    //Remove this portion -- going to be empty CT
    //do a memcpy for goat strtok to replace : 
    //then a strtolower
    //copy the result in list->ct
    //

    char ct_final[1024];
    memset(ct_final,0,1024);

        int i = 0;
        int kay = 0;
        while(goat[i] != NULL)
        {
            //if(strrchr(ct_final[i],':'
            if(goat[i]!=':')
            {
                ct_final[kay] = tolower(goat[i]);
                //printf("%c", tolower(goat[i]));
                kay++;
            }
            i++;

        }


    if(list->vectortest == 0)
    {
        strncpy(list->ct, ct_final, strlen(ct_final));
        list->pass = 1;

    }
/////////
    if(list->vectortest == 1) //We can only verify and copy if FAX or 1
    {
        if(strncmp(ct_final,list->ct, strlen(list->ct)) == 0)
        {
            strncpy(list->ciphreport, ct_final, strlen(ct_final));
            list->pass = 1;
            printf("PASS Count:%i %s%i\n",list->vcount, list->testtype, list->ciphertype);
            printf("Ciphertext: %s\n", list->ciphreport);
            printf("Plaintext: %s\n", list->pt);
            printf("Key: %s\n\n", list->key);
        }
        else
        {
            strcpy(list->ciphreport, list->ct);
            list->pass = 0;
            printf("FAIL Count:%i %s%i\n",list->vcount, list->testtype,list->ciphertype);
            printf("Failed Ciphertext: %s\n", goat);
            printf("Ciphertext: %s\n", list->ct);
            printf("Plaintext: %s\n", list->pt);
            exit(-1);
        }
    }


    return 0;
}

int main(int argc, char *argv[]) 
{
    int vectortest = 0; //0:Req 1: Fax
    char vectortestext[4];

    char  aes_dir[1024];
    memset(aes_dir,0,1024);

    char  aes_fax_dir[]= "./Leidos_Vectors/AES/fax/";
    char  aes_req_dir[]= "./Leidos_Vectors/AES/req/";

    switch (vectortest)
    {
        case 0: //we are doing a requests file
            strncpy(vectortestext,".req",strlen(vectortestext));
            strncpy(aes_dir,aes_req_dir, strlen(aes_req_dir));
            break;
        case 1: //we are doing a fax file
            strncpy(vectortestext,".fax",strlen(vectortestext));
            strncpy(aes_dir,aes_fax_dir, strlen(aes_req_dir));
            break;
    }

    char fbuff[1024];
    char nbuff[20];//name_buffer
    char cbuff[20];//cipher_type
    struct dirent* de;


    DIR *dr = opendir(aes_dir);
    FILE * VectorFile;

    if (dr == NULL)
        printf("Empty Directory");

    //Create structure
    struct vectors* head = NULL;
    struct vectors* sentinal= NULL;

    head = (struct vectors*)malloc(sizeof(struct vectors));
    sentinal = head;

    sentinal->testnumber = 0; //start off the first record as zero
    sentinal->next = NULL; //next pointer is null until parser sees otherwise

    //Go through all the files in that directory and send file descriptor off to process

    while ((de = readdir(dr)) != NULL)
    {
        if(strstr(de->d_name,vectortestext))
        {
            memset(fbuff,0,1024);
            memset(nbuff,0,20);
            memcpy(nbuff,de->d_name,strlen(de->d_name)-7); //contains test type
            memcpy(cbuff,de->d_name+strlen(nbuff),3); //contains test type
            strncpy(fbuff,aes_dir,sizeof(aes_dir));
            strcat(fbuff,de->d_name);
            //printf("%s\n", de->d_name);
            //VectorFile = fopen(de->d_name, "r");
            VectorFile = fopen(fbuff, "r");

            if(VectorFile == NULL)
            {
                printf("Can not open Vector File\n");
                return -1;
            }


            printf("Whole Name: %s \n",fbuff);
            printf("Type is: %s at %i\n", nbuff,atoi(cbuff));
            //grab the address of the last structure

            //Parse the files

            if(strncmp(nbuff, "ECBMCT",6)==0)
            {
                sentinal = mct_vector_parse(sentinal, VectorFile, nbuff, atoi(cbuff), vectortest);
            }else
            {
                sentinal = vector_parse(sentinal, VectorFile, nbuff, atoi(cbuff), vectortest);
            }
        }
    }
    closedir(dr);
    sentinal = head;
    while(sentinal->next!= NULL)
    {
        printf("Record Number: %i \n",sentinal->testnumber);
        printf("File %s\n", sentinal->testtype);
        printf("AES-%i-ECB\n", sentinal->ciphertype);
        printf("Key:%s\n", sentinal->key);
        printf("Plaintext:%s\n", sentinal->pt);

        if(strncmp(sentinal->testtype, "ECBMCT", 6) == 0)
        {
            process_mct(sentinal);
        }
        else
        {
            process(sentinal);
        }
        //printf("Record Number: %i \n",rn);
        printf("Final Ciphertext:%s\n\n", sentinal->ct);
        sentinal = sentinal->next;
    }

    sentinal = head;

    vector_write(sentinal);

}
