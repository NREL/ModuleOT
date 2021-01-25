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
#include <dirent.h>

//For this harness we:
//1. Process all the files based on vector type into a linked list.
//2. The linked list is then parsed.
//3. Encryption/Decryption is done with results populated.
//4. Output files are then generated. For Fax, results are compared and written out.h

struct vectors {
    unsigned int testnumber;      //Which test number are we working with  (i.e. 0 - all the leidos vectors)
    unsigned int testresult;      //0: Fail 1: Pass - We will be using this for Fax Verification
    unsigned int vectortest;      //0: Req 1:Fax
    unsigned int result;          //This is for the actual vector result. Some are supposed to fail. 0: fail 1: pass
    unsigned int fax_result;          //This is for the actual vector result. Some are supposed to fail. 0: fail 1: pass
    char testtype[1024];          //DVPT, VADT, VNT, VPT, VTT
    char filename[1024];          //File Name
    int ciphertype;               //AES-128,192,256
    int alen, plen, nlen, tlen, count; //These are parameters which should be filled
    unsigned char key[1024];           //The actual key for decryption/encryption
    unsigned char nonce[1024];         //The Initialization Vector
    unsigned char adata[140000]; //
    unsigned char ciphertext[1024]; //
    unsigned char payload[1024]; //
    unsigned char fax_payload[1024]; //String to compare to
    unsigned char ct[1024]; //DVPT-CipherText
    struct vectors* next;
};

//Individual Test Text Parsers
struct vectors*  dvpt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest);
struct vectors*  vadt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest);
struct vectors*  vnt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest);
struct vectors*  vpt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest);
struct vectors*  vtt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest);
int vector_encrypt(struct vectors* sentinal);
int vector_decrypt(struct vectors* sentinal);
//Generate the response files
int vector_response(struct vectors* sentinal);
struct vectors* vector_resp_dvpt(struct vectors* sentinal);
struct vectors* vector_resp_vadt(struct vectors* sentinal);
struct vectors* vector_resp_vnt(struct vectors* sentinal);
struct vectors* vector_resp_vpt(struct vectors* sentinal);
struct vectors* vector_resp_vtt(struct vectors* sentinal);

struct vectors* vector_resp_vtt(struct vectors* sentinal)
{
    FILE * ResponseFile;
    char respname[1024];
    memset(respname,0,1024);
    char cident[4];
    char wdata[1024];
    memset(wdata,0,1024);
                
    switch (sentinal->ciphertype)
                {
                    case 128:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VTT128.rsp");
                        strcpy(cident,"128");
                        break;
                    case 192:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VTT192.rsp");
                        strcpy(cident,"192");
                        break;
                    case 256:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VTT256.rsp");
                        strcpy(cident,"256");
                        break;
                }

    time_t now;
    char * ascii_payload;
    char * header1_fmt = "# CAVS 21.4\n";
    char * header2_fmt = "# NREL CCM-VTT\n";
    char * header3_fmt = "# AES VTT";
    char * header6_fmt = "# Generated on ";
    char * break_fmt="\n";

    printf("The write file is %s\n", respname);

    ResponseFile = fopen(respname, "w");

            
    fwrite(header1_fmt, 1,strlen(header1_fmt), ResponseFile);
    fwrite(header2_fmt, 1,strlen(header2_fmt), ResponseFile);
    fwrite(header3_fmt, 1,strlen(header3_fmt), ResponseFile);
    fwrite(cident, 1,strlen(cident), ResponseFile);

    fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);


    time(&now);
    fwrite(header6_fmt, 1,strlen(header6_fmt), ResponseFile);
    fprintf(ResponseFile, "%s\n", ctime(&now));
    //fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
            
    ///Finished Writing Header
    
    sprintf(wdata,"Alen = %i\nPlen = %i\nNlen = %i\n\n", sentinal->alen, sentinal->plen, sentinal->nlen);
    fwrite(wdata, 1,strlen(wdata), ResponseFile);
    memset(wdata,0,1024);
   
    while(sentinal->next != NULL)
    {
        if((sentinal->count % 10) == 0)
        {
            sprintf(wdata,"[Tlen = %i]\n\n", sentinal->tlen);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

            sprintf(wdata,"Key = %s\n", sentinal->key);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

            sprintf(wdata,"Nonce = %s\n\n", sentinal->nonce);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);
        }

        sprintf(wdata,"Count = %i\n", sentinal->count);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);


        sprintf(wdata,"Adata = %s\n", sentinal->adata);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        sprintf(wdata,"Payload = %s\n", sentinal->payload);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        sprintf(wdata,"CT = %s\n\n", sentinal->ct);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        if(sentinal->next->count == 0)
            return sentinal; 

        sentinal = sentinal->next;

    }

    return sentinal; 

}
struct vectors* vector_resp_vpt(struct vectors* sentinal)
{
    FILE * ResponseFile;
    char respname[1024];
    memset(respname,0,1024);
    char cident[4];
    char wdata[1024];
    memset(wdata,0,1024);
                
    switch (sentinal->ciphertype)
                {
                    case 128:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VPT128.rsp");
                        strcpy(cident,"128");
                        break;
                    case 192:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VPT192.rsp");
                        strcpy(cident,"192");
                        break;
                    case 256:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VPT256.rsp");
                        strcpy(cident,"256");
                        break;
                }

    time_t now;
    char * ascii_payload;
    char * header1_fmt = "# CAVS 21.4\n";
    char * header2_fmt = "# NREL CCM-VPT\n";
    char * header3_fmt = "# AES VPT";
    char * header6_fmt = "# Generated on ";
    char * break_fmt="\n";

    printf("The write file is %s\n", respname);

    ResponseFile = fopen(respname, "w");

            
    fwrite(header1_fmt, 1,strlen(header1_fmt), ResponseFile);
    fwrite(header2_fmt, 1,strlen(header2_fmt), ResponseFile);
    fwrite(header3_fmt, 1,strlen(header3_fmt), ResponseFile);
    fwrite(cident, 1,strlen(cident), ResponseFile);

    fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);


    time(&now);
    fwrite(header6_fmt, 1,strlen(header6_fmt), ResponseFile);
    fprintf(ResponseFile, "%s\n", ctime(&now));
    //fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
            
    ///Finished Writing Header
    
    sprintf(wdata,"Alen = %i\nNlen = %i\nTlen = %i\n\n", sentinal->alen, sentinal->nlen, sentinal->tlen);
    fwrite(wdata, 1,strlen(wdata), ResponseFile);
    memset(wdata,0,1024);

    while(sentinal->next != NULL)
    {
        if((sentinal->count % 10) == 0)
        {
            sprintf(wdata,"[Plen = %i]\n\n", sentinal->plen);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

            sprintf(wdata,"Key = %s\n", sentinal->key);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

            sprintf(wdata,"Nonce = %s\n\n", sentinal->nonce);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);
        }

        sprintf(wdata,"Count = %i\n", sentinal->count);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);


        sprintf(wdata,"Adata = %s\n", sentinal->adata);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        sprintf(wdata,"Payload = %s\n", sentinal->payload);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        sprintf(wdata,"CT = %s\n\n", sentinal->ct);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        if(sentinal->next->count == 0)
            return sentinal; 

        sentinal = sentinal->next;

    }
    return sentinal; 

}
struct vectors* vector_resp_vnt(struct vectors* sentinal)
{
    FILE * ResponseFile;
    char respname[1024];
    memset(respname,0,1024);
    char cident[4];
    char wdata[1024];
    memset(wdata,0,1024);
                
    switch (sentinal->ciphertype)
                {
                    case 128:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VNT128.rsp");
                        strcpy(cident,"128");
                        break;
                    case 192:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VNT192.rsp");
                        strcpy(cident,"192");
                        break;
                    case 256:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VNT256.rsp");
                        strcpy(cident,"256");
                        break;
                }

    time_t now;
    char * ascii_payload;
    char * header1_fmt = "# CAVS 21.4\n";
    char * header2_fmt = "# NREL CCM-VNT\n";
    char * header3_fmt = "# AES VNT";
    char * header6_fmt = "# Generated on ";
    char * break_fmt="\n";

    printf("The write file is %s\n", respname);

    ResponseFile = fopen(respname, "w");

            
    fwrite(header1_fmt, 1,strlen(header1_fmt), ResponseFile);
    fwrite(header2_fmt, 1,strlen(header2_fmt), ResponseFile);
    fwrite(header3_fmt, 1,strlen(header3_fmt), ResponseFile);
    fwrite(cident, 1,strlen(cident), ResponseFile);

    fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);


    time(&now);
    fwrite(header6_fmt, 1,strlen(header6_fmt), ResponseFile);
    fprintf(ResponseFile, "%s\n", ctime(&now));
    //fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
            
    ///Finished Writing Header
    
    sprintf(wdata,"Alen = %i\nPlen = %i\nTlen = %i\n\n", sentinal->alen, sentinal->plen, sentinal->tlen);
    fwrite(wdata, 1,strlen(wdata), ResponseFile);
    memset(wdata,0,1024);
    
    while(sentinal->next != NULL)
    {
        if((sentinal->count % 10) == 0)
        {
            sprintf(wdata,"[Nlen = %i]\n\n", sentinal->nlen);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

            sprintf(wdata,"Key = %s\n\n", sentinal->key);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);
        }

        sprintf(wdata,"Count = %i\n", sentinal->count);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        sprintf(wdata,"Nonce = %s\n", sentinal->nonce);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);


        sprintf(wdata,"Adata = %s\n", sentinal->adata);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        sprintf(wdata,"Payload = %s\n", sentinal->payload);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);
        sprintf(wdata,"CT = %s\n\n", sentinal->ct);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        if(sentinal->next->count == 0)
            return sentinal; 

        sentinal = sentinal->next;

    }

    return sentinal; 
}

struct vectors* vector_resp_vadt(struct vectors* sentinal)
{
    FILE * ResponseFile;
    char respname[1024];
    memset(respname,0,1024);
    char cident[4];
    char wdata[1024];
    memset(wdata,0,1024);
    char lwdata[140000]; //File buffer
    memset(lwdata,0,140000);
                
    switch (sentinal->ciphertype)
                {
                    case 128:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VADT128.rsp");
                        strcpy(cident,"128");
                        break;
                    case 192:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VADT192.rsp");
                        strcpy(cident,"192");
                        break;
                    case 256:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/VADT256.rsp");
                        strcpy(cident,"256");
                        break;
                }

    time_t now;
    char * ascii_payload;
    char * header1_fmt = "# CAVS 21.4\n";
    char * header2_fmt = "# NREL CCM-VADT\n";
    char * header3_fmt = "# AES VADT";
    char * header6_fmt = "# Generated on ";
    char * break_fmt="\n";

    printf("The write file is %s\n", respname);

    ResponseFile = fopen(respname, "w");

            
    fwrite(header1_fmt, 1,strlen(header1_fmt), ResponseFile);
    fwrite(header2_fmt, 1,strlen(header2_fmt), ResponseFile);
    fwrite(header3_fmt, 1,strlen(header3_fmt), ResponseFile);
    fwrite(cident, 1,strlen(cident), ResponseFile);

    fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);


    time(&now);
    fwrite(header6_fmt, 1,strlen(header6_fmt), ResponseFile);
    fprintf(ResponseFile, "%s\n", ctime(&now));
    //fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
    ///Finished Writing Header
    
    sprintf(wdata,"Plen = %i\nNlen = %i\nTlen = %i\n\n", sentinal->plen, sentinal->nlen, sentinal->tlen);
    fwrite(wdata, 1,strlen(wdata), ResponseFile);
    memset(wdata,0,1024);

    while(sentinal->next != NULL)
    {
        if((sentinal->count % 10) == 0)
        {
            sprintf(wdata,"[Alen = %i]\n\n", sentinal->alen);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

            sprintf(wdata,"Key = %s\n", sentinal->key);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

            sprintf(wdata,"Nonce = %s\n\n", sentinal->nonce);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

        }

        sprintf(wdata,"Count = %i\n", sentinal->count);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);
        
        sprintf(lwdata,"Adata = %s\n", sentinal->adata);
        //sprintf(lwdata,"Adata = \n");
        fwrite(lwdata, 1,strlen(lwdata), ResponseFile);
        memset(lwdata,0,140000);

        sprintf(wdata,"Payload = %s\n", sentinal->payload);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);
        sprintf(wdata,"CT = %s\n\n", sentinal->ct);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        if(sentinal->next->count == 0)
            return sentinal; 

        sentinal = sentinal->next;

    }

    return sentinal; 
}
struct vectors* vector_resp_dvpt(struct vectors* sentinal)
{
    FILE * ResponseFile;
    char respname[1024];
    memset(respname,0,1024);
    char cident[4];
    char wdata[1024];
    memset(wdata,0,1024);
                
    switch (sentinal->ciphertype)
                {
                    case 128:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/DVPT128.rsp");
                        strcpy(cident,"128");
                        break;
                    case 192:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/DVPT192.rsp");
                        strcpy(cident,"192");
                        break;
                    case 256:
                        strcpy(respname,"./Leidos_Vectors/CCM/resp/DVPT256.rsp");
                        strcpy(cident,"256");
                        break;
                }

    time_t now;
    char * ascii_payload;
    char * header1_fmt = "# CAVS 21.4\n";
    char * header2_fmt = "# NREL CCM-DVPT\n";
    char * header3_fmt = "# AES DVPT ";
    char * header6_fmt = "# Generated on ";
    char * break_fmt="\n";

    printf("The write file is %s\n", respname);

    ResponseFile = fopen(respname, "w");

            
    fwrite(header1_fmt, 1,strlen(header1_fmt), ResponseFile);
    fwrite(header2_fmt, 1,strlen(header2_fmt), ResponseFile);
    fwrite(header3_fmt, 1,strlen(header3_fmt), ResponseFile);
    fwrite(cident, 1,strlen(cident), ResponseFile);

    fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);


    time(&now);
    fwrite(header6_fmt, 1,strlen(header6_fmt), ResponseFile);
    fprintf(ResponseFile, "%s\n", ctime(&now));
    fwrite(break_fmt, 1,strlen(break_fmt), ResponseFile);
    
    ///Finished Writing Header

    while(sentinal->next != NULL)
    {
        if((sentinal->count % 15) == 0)
        {
            sprintf(wdata,"[Alen = %i, Plen = %i, Nlen = %i, Tlen = %i]\n\n", sentinal->alen, sentinal->plen, sentinal->nlen, sentinal->tlen);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);
            
            sprintf(wdata,"Key = %s\n\n", sentinal->key);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);

        }

        sprintf(wdata,"Count = %i\n", sentinal->count);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);
        sprintf(wdata,"Nonce = %s\n", sentinal->nonce);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);
        sprintf(wdata,"Adata = %s\n", sentinal->adata);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);
        sprintf(wdata,"CT = %s\n", sentinal->ct);
        fwrite(wdata, 1,strlen(wdata), ResponseFile);
        memset(wdata,0,1024);

        if(sentinal->result == 0) //fail
        {
            sprintf(wdata,"Result = Fail\n\n");
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);
        }

        //int i = 0;
        
        if(sentinal->result == 1) //fail
        {
            //payload output should be in ascii


            sprintf(wdata,"Result = Pass\nPayload = %s\n\n",sentinal->payload);// sentinal->payload);
            fwrite(wdata, 1,strlen(wdata), ResponseFile);
            memset(wdata,0,1024);
           
            /*
            ascii_payload = OPENSSL_buf2hexstr(sentinal->payload, sentinal->plen);
            while(ascii_payload[i] != NULL)
            {
                //if(strrchr(ct_final[i],':'
                if(ascii_payload[i]!=':')
                {
                    sprintf(wdata,"%s",ascii_payload[i]);// sentinal->payload);
                    fwrite(wdata, 1,strlen(wdata), ResponseFile);
                    memset(wdata,0,1024);
                
                    //fwrite(tolower(ascii_payload[i]),1,1,ResponseFile);
                    fwrite(wdata,1,1,ResponseFile);

                }
                i++;

            }*/
        }


            if(sentinal->next->count == 0)
                return sentinal; 

            sentinal = sentinal->next;

    }

    //strncpy(respname, data, dlen-3); //3 removes control characters...magic numbers


    return sentinal; 
}

//Process fax or requests file data into structure
struct vectors* vtt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest)
{
    char filestream[1024]; //File buffer
    char *data; //Buffer 
    int dlen, vtt_p_alen, vtt_p_plen, vtt_p_nlen, vtt_p_tlen;
    char vpt_key[1024];
    char vpt_nonce[1024];
    int linenum = 0;
    int curr_testnumber= sentinal->testnumber; //grab the current test number
    
    unsigned char * h_key;
    long hex_keylen, hex_noncelen, hex_adatalen, hex_ciphertextlen,hex_payloadlen ;

    //Something has gone wrong, we should always be starting with a NULL
    if(sentinal->next!=NULL)
    {
        printf("Bad Book Keeping");
        exit(-1);
    }
    
    //read the entire file and parse out fields into the structure
    while(fgets(filestream, sizeof(filestream), vparse))
    {
        if(strstr(filestream,"\n")!=NULL)
        {
            linenum++;
        }

        if(strncmp(filestream, "Alen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->alen = atoi(data);
            vtt_p_alen = sentinal->alen;
        }
        if(strncmp(filestream, "Plen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->plen = atoi(data);
            vtt_p_plen = sentinal->plen;
        }
        if(strncmp(filestream, "Nlen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->nlen = atoi(data);
            vtt_p_nlen = sentinal->nlen;
        }
        if(strncmp(filestream, "[Tlen =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->tlen = atoi(data);
            vtt_p_tlen = sentinal->tlen;
        }
        
        if(strncmp(filestream, "Key =",5)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data); //Get the original size

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data)); //copy data from temporary pointer

            memset(sentinal->key,0,1024); //Clear
            strncpy(sentinal->key, data, dlen-3); //3 removes control characters...magic numbers
            memset(vpt_key, 0, 1024);
            strncpy(vpt_key, sentinal->key, strlen(sentinal->key)); //3 removes control characters...magic numbers
        }
        if(strncmp(filestream, "Nonce =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data);
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            memset(sentinal->nonce,0,1024); //Clear
            strncpy(sentinal->nonce, data, dlen-3);
            memset(vpt_nonce, 0, 1024);
            strncpy(vpt_nonce, sentinal->nonce, strlen(sentinal->nonce)); //3 removes control characters...magic numbers
        }
        //Parse the Count
        if(strncmp(filestream, "Count =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->count = atoi(data);
            sentinal->vectortest = vectortest; //tell us if fax or req
            sentinal->ciphertype= ciphersize; //128, 192, 256
            strncpy(sentinal->testtype, fname, strlen(fname)); //set its vpt
        }


        //Plen, Nlen, Tlen do not change for vpt
        sentinal->alen = vtt_p_alen;
        sentinal->plen = vtt_p_plen;
        sentinal->nlen = vtt_p_nlen;

        //every 10 the  key, plen, and nonce change
        if(((sentinal->count % 10) > 0) && (!strncmp(fname, "VTT", strlen(fname))))
            if(!strncmp(fname, "VTT", strlen(fname)))
            {
                sentinal->tlen = vtt_p_tlen;
                strncpy(sentinal->key,vpt_key, strlen(vpt_key)); //3 removes control characters...magic numbers
                strncpy(sentinal->nonce,vpt_nonce, strlen(vpt_nonce)); //3 removes control characters...magic numbers
            }

        if(strncmp(filestream, "Adata =",7)==0)
        {
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                strncpy(sentinal->adata, data, strlen(data)-2);
        }
        if(strncmp(filestream, "Payload =",9)==0 )
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->payload, data, strlen(data)-2);
                
            if(vectortest == 0)//If we are doing a fax file (1), then ignore this
            {
                /*
                printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Cipher Size = %i\n", sentinal->ciphertype);
                printf("Key = %s\n", sentinal->key);
                printf("Nonce = %s\n", sentinal->nonce);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("alen = %i\n", sentinal->alen);
                
                printf("\nCount = %i\n", sentinal->count);
                printf("Adata = %s\n", sentinal->adata);
                printf("Payload = %s\n", sentinal->payload);
                */

                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }
        
        if((strncmp(filestream, "CT =",4)==0) && (!strncmp(fname, "VTT", strlen(fname))))
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->ct, data, strlen(data)-2);


            if(vectortest == 1)//If we are doing a fax file (1), then ignore this
            {
                /*
                printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Cipher Size = %i\n", sentinal->ciphertype);
                printf("Key = %s\n", sentinal->key);
                printf("Nonce = %s\n", sentinal->nonce);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("alen = %i\n", sentinal->alen);
                
                printf("\nCount = %i\n", sentinal->count);
                printf("Adata = %s\n", sentinal->adata);
                printf("Payload = %s\n", sentinal->payload);
                printf("CT = %s\n", sentinal->ct);
                */
                
                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }

    }

    
    return sentinal;
}
struct vectors* vpt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest)
{
    char filestream[1024]; //File buffer
    char *data; //Buffer 
    int dlen, vpt_p_alen, vpt_p_plen, vpt_p_nlen, vpt_p_tlen;
    char vpt_key[1024];
    char vpt_nonce[1024];
    int linenum = 0;
    int curr_testnumber= sentinal->testnumber; //grab the current test number
    
    unsigned char * h_key;
    long hex_keylen, hex_noncelen, hex_adatalen, hex_ciphertextlen,hex_payloadlen ;

    //Something has gone wrong, we should always be starting with a NULL
    if(sentinal->next!=NULL)
    {
        printf("Bad Book Keeping");
        exit(-1);
    }
    
    //read the entire file and parse out fields into the structure
    while(fgets(filestream, sizeof(filestream), vparse))
    {
        if(strstr(filestream,"\n")!=NULL)
        {
            linenum++;
        }

        if(strncmp(filestream, "Alen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->alen = atoi(data);
            vpt_p_alen = sentinal->alen;
        }

        if(strncmp(filestream, "Nlen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->nlen = atoi(data);
            vpt_p_nlen = sentinal->nlen;
        }
        if(strncmp(filestream, "Tlen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->tlen = atoi(data);
            vpt_p_tlen = sentinal->tlen;
        }
        if(strncmp(filestream, "[Plen =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->plen = atoi(data);
            vpt_p_plen = sentinal->plen;
        }
        
        if(strncmp(filestream, "Key =",5)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data); //Get the original size

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data)); //copy data from temporary pointer

            memset(sentinal->key,0,1024); //Clear
            strncpy(sentinal->key, data, dlen-3); //3 removes control characters...magic numbers
            memset(vpt_key, 0, 1024);
            strncpy(vpt_key, sentinal->key, strlen(sentinal->key)); //3 removes control characters...magic numbers
        }
        if(strncmp(filestream, "Nonce =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data);
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            memset(sentinal->nonce,0,1024); //Clear
            strncpy(sentinal->nonce, data, dlen-3);
            memset(vpt_nonce, 0, 1024);
            strncpy(vpt_nonce, sentinal->nonce, strlen(sentinal->nonce)); //3 removes control characters...magic numbers
        }
        //Parse the Count
        if(strncmp(filestream, "Count =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->count = atoi(data);
            sentinal->vectortest = vectortest; //tell us if fax or req
            sentinal->ciphertype= ciphersize; //128, 192, 256
            strncpy(sentinal->testtype, fname, strlen(fname)); //set its vpt
        }


        //Plen, Nlen, Tlen do not change for vpt
        sentinal->alen = vpt_p_alen;
        sentinal->nlen = vpt_p_nlen;
        sentinal->tlen = vpt_p_tlen;

        //every 10 the  key, plen, and nonce change
        if(((sentinal->count % 10) > 0) && (!strncmp(fname, "VPT", strlen(fname))))
            if(!strncmp(fname, "VPT", strlen(fname)))
            {
                sentinal->plen = vpt_p_plen;
                strncpy(sentinal->key,vpt_key, strlen(vpt_key)); //3 removes control characters...magic numbers
                strncpy(sentinal->nonce,vpt_nonce, strlen(vpt_nonce)); //3 removes control characters...magic numbers
            }

        if(strncmp(filestream, "Adata =",7)==0)
        {
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                strncpy(sentinal->adata, data, strlen(data)-2);
        }
        if(strncmp(filestream, "Payload =",9)==0 )
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->payload, data, strlen(data)-2);
                
            if(vectortest == 0)//If we are doing a fax file (1), then ignore this
            {
                /*
                printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Cipher Size = %i\n", sentinal->ciphertype);
                printf("Key = %s\n", sentinal->key);
                printf("Nonce = %s\n", sentinal->nonce);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("alen = %i\n", sentinal->alen);
                
                printf("\nCount = %i\n", sentinal->count);
                printf("Adata = %s\n", sentinal->adata);
                printf("Payload = %s\n", sentinal->payload);
                */

                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }
        
        if((strncmp(filestream, "CT =",4)==0) && (!strncmp(fname, "VPT", strlen(fname))))
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->ct, data, strlen(data)-2);


            if(vectortest == 1)//If we are doing a fax file (1), then ignore this
            {
                /*
                printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Cipher Size = %i\n", sentinal->ciphertype);
                printf("Key = %s\n", sentinal->key);
                printf("Nonce = %s\n", sentinal->nonce);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("alen = %i\n", sentinal->alen);
                
                printf("\nCount = %i\n", sentinal->count);
                printf("Adata = %s\n", sentinal->adata);
                printf("Payload = %s\n", sentinal->payload);
                printf("CT = %s\n", sentinal->ct);
               */

                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }

    }

    
    return sentinal;
}
struct vectors* vnt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest)
{
    char filestream[1024]; //File buffer
    char *data; //Buffer 
    int dlen, vnt_p_alen, vnt_p_plen, vnt_p_nlen, vnt_p_tlen;
    char vnt_key[1024];
    int linenum = 0;
    int curr_testnumber= sentinal->testnumber; //grab the current test number
    
    unsigned char * h_key;
    long hex_keylen, hex_noncelen, hex_adatalen, hex_ciphertextlen,hex_payloadlen ;

    //Something has gone wrong, we should always be starting with a NULL
    if(sentinal->next!=NULL)
    {
        printf("Bad Book Keeping");
        exit(-1);
    }
    
    //read the entire file and parse out fields into the structure
    while(fgets(filestream, sizeof(filestream), vparse))
    {
        if(strstr(filestream,"\n")!=NULL)
        {
            linenum++;
        }
        
        if(strncmp(filestream, "Alen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->alen = atoi(data);
            vnt_p_alen = sentinal->alen;
        }

        if(strncmp(filestream, "Plen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->plen = atoi(data);
            vnt_p_plen = sentinal->plen;
        }

        if(strncmp(filestream, "Tlen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->tlen = atoi(data);
            vnt_p_tlen = sentinal->tlen;
        }
        if(strncmp(filestream, "[Nlen =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->nlen = atoi(data);
            vnt_p_nlen = sentinal->nlen;
        }
        
        if(strncmp(filestream, "Key =",5)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data); //Get the original size

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data)); //copy data from temporary pointer

            memset(sentinal->key,0,1024); //Clear
            strncpy(sentinal->key, data, dlen-3); //3 removes control characters...magic numbers
            memset(vnt_key, 0, 1024);
            strncpy(vnt_key, sentinal->key, strlen(sentinal->key)); //3 removes control characters...magic numbers
        }
        
        //Parse the Count
        if(strncmp(filestream, "Count =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->count = atoi(data);
            sentinal->vectortest = vectortest; //tell us if fax or req
            sentinal->ciphertype= ciphersize; //128, 192, 256
            strncpy(sentinal->testtype, fname, strlen(fname)); //set its vadt
        }
        if(strncmp(filestream, "Nonce =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data);
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            memset(sentinal->nonce,0,1024); //Clear
            strncpy(sentinal->nonce, data, dlen-3);
        }


        //Plen, Nlen, Tlen do not change for vadt
        sentinal->alen = vnt_p_alen;
        sentinal->plen = vnt_p_plen;
        sentinal->tlen = vnt_p_tlen;

        //every 10 the  key, alen, and nonce change
        if(((sentinal->count % 10) > 0) && (!strncmp(fname, "VNT", strlen(fname))))
            if(!strncmp(fname, "VNT", strlen(fname)))
            {
                sentinal->nlen = vnt_p_nlen;
                strncpy(sentinal->key,vnt_key, strlen(vnt_key)); //3 removes control characters...magic numbers
            }

        if(strncmp(filestream, "Adata =",7)==0)
        {
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                strncpy(sentinal->adata, data, strlen(data)-2);
        }
        if(strncmp(filestream, "Payload =",9)==0 )
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->payload, data, strlen(data)-2);
                
            if(vectortest == 0)//If we are doing a fax file (1), then ignore this
            {
                /*
                printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Cipher Size = %i\n", sentinal->ciphertype);
                printf("Key = %s\n", sentinal->key);
                printf("Nonce = %s\n", sentinal->nonce);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("alen = %i\n", sentinal->alen);
                
                printf("\nCount = %i\n", sentinal->count);
                printf("Adata = %s\n", sentinal->adata);
                printf("Payload = %s\n", sentinal->payload);
*/

                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }
        
        if((strncmp(filestream, "CT =",4)==0) && (!strncmp(fname, "VNT", strlen(fname))))
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->ct, data, strlen(data)-2);


            if(vectortest == 1)//If we are doing a fax file (1), then ignore this
            {
                /*
                printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Cipher Size = %i\n", sentinal->ciphertype);
                printf("Key = %s\n", sentinal->key);
                printf("Nonce = %s\n", sentinal->nonce);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("alen = %i\n", sentinal->alen);
                
                printf("\nCount = %i\n", sentinal->count);
                printf("Adata = %s\n", sentinal->adata);
                printf("Payload = %s\n", sentinal->payload);
                printf("CT = %s\n", sentinal->ct);
                */ 
                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }

    }

    
    return sentinal;
}
struct vectors* vadt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest)
{
    //char filestream[1024]; //File buffer
    char filestream[140000]; //File buffer
    char *data; //Buffer 
    int dlen, vadt_p_alen, vadt_p_plen, vadt_p_nlen, vadt_p_tlen;
    char vadt_key[1024];
    char vadt_nonce[1024];
    int linenum = 0;
    int curr_testnumber= sentinal->testnumber; //grab the current test number
    
    unsigned char * h_key;
    long hex_keylen, hex_noncelen, hex_adatalen, hex_ciphertextlen,hex_payloadlen ;

    //Something has gone wrong, we should always be starting with a NULL
    if(sentinal->next!=NULL)
    {
        printf("Bad Book Keeping");
        exit(-1);
    }
    
    //read the entire file and parse out fields into the structure
    while(fgets(filestream, sizeof(filestream), vparse))
    {
        if(strstr(filestream,"\n")!=NULL)
        {
            linenum++;
        }

        if(strncmp(filestream, "Plen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->plen = atoi(data);
            vadt_p_plen = sentinal->plen;
        }

        if(strncmp(filestream, "Nlen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->nlen = atoi(data);
            vadt_p_nlen = sentinal->nlen;
        }
        if(strncmp(filestream, "Tlen =",6)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->tlen = atoi(data);
            vadt_p_tlen = sentinal->tlen;
        }
        if(strncmp(filestream, "[Alen =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->alen = atoi(data);
            vadt_p_alen = sentinal->alen;
        }
        
        if(strncmp(filestream, "Key =",5)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data); //Get the original size

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data)); //copy data from temporary pointer

            memset(sentinal->key,0,1024); //Clear
            strncpy(sentinal->key, data, dlen-3); //3 removes control characters...magic numbers
            memset(vadt_key, 0, 1024);
            strncpy(vadt_key, sentinal->key, strlen(sentinal->key)); //3 removes control characters...magic numbers
        }
        if(strncmp(filestream, "Nonce =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data);
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            memset(sentinal->nonce,0,1024); //Clear
            strncpy(sentinal->nonce, data, dlen-3);
            memset(vadt_nonce, 0, 1024);
            strncpy(vadt_nonce, sentinal->nonce, strlen(sentinal->nonce)); //3 removes control characters...magic numbers
        }
        //Parse the Count
        if(strncmp(filestream, "Count =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->count = atoi(data);
            sentinal->vectortest = vectortest; //tell us if fax or req
            sentinal->ciphertype= ciphersize; //128, 192, 256
            strncpy(sentinal->testtype, fname, strlen(fname)); //set its vadt
        }


        //Plen, Nlen, Tlen do not change for vadt
        sentinal->plen = vadt_p_plen;
        sentinal->nlen = vadt_p_nlen;
        sentinal->tlen = vadt_p_tlen;

        //every 10 the  key, alen, and nonce change
        if(((sentinal->count % 10) > 0) && (!strncmp(fname, "VADT", strlen(fname))))
            if(!strncmp(fname, "VADT", strlen(fname)))
            {
                sentinal->alen = vadt_p_alen;
                strncpy(sentinal->key,vadt_key, strlen(vadt_key)); //3 removes control characters...magic numbers
                strncpy(sentinal->nonce,vadt_nonce, strlen(vadt_nonce)); //3 removes control characters...magic numbers
            }

        if(strncmp(filestream, "Adata =",7)==0)
        {
                data = strtok(filestream, "=");
                data = strtok(NULL,"=");
                if(data[0] == ' ')
                    memmove(data, data+1, strlen(data));
                strncpy(sentinal->adata, data, strlen(data)-2);
        }
        if(strncmp(filestream, "Payload =",9)==0 )
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->payload, data, strlen(data)-2);
                
            if(vectortest == 0)//If we are doing a fax file (1), then ignore this
            {
                /*
                printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Cipher Size = %i\n", sentinal->ciphertype);
                printf("Key = %s\n", sentinal->key);
                printf("Nonce = %s\n", sentinal->nonce);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("alen = %i\n", sentinal->alen);
                
                printf("\nCount = %i\n", sentinal->count);
                printf("Adata = %s\n", sentinal->adata);
                printf("Payload = %s\n", sentinal->payload);
                */

                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }
        
        if((strncmp(filestream, "CT =",4)==0) && (!strncmp(fname, "VADT", strlen(fname))))
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->ct, data, strlen(data)-2);


            if(vectortest == 1)//If we are doing a fax file (1), then ignore this
            {
                /*
                printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Cipher Size = %i\n", sentinal->ciphertype);
                printf("Key = %s\n", sentinal->key);
                printf("Nonce = %s\n", sentinal->nonce);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("alen = %i\n", sentinal->alen);
                
                printf("\nCount = %i\n", sentinal->count);
                printf("Adata = %s\n", sentinal->adata);
                printf("Payload = %s\n", sentinal->payload);
                printf("CT = %s\n", sentinal->ct);
                */
                
                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }

    }

    
    return sentinal;
}

//Parse all the dvpt test vectors given the linked lisst, the file pointer, fileanme, ciphersize, and fax or req
struct vectors* dvpt_vector_parse(struct vectors* sentinal, FILE * vparse, char * fname, int ciphersize, int vectortest)
{
    char filestream[1024]; //File buffer
    char *data; //Buffer 
    int dlen, dvpt_p_alen, dvpt_p_plen, dvpt_p_nlen, dvpt_p_tlen;
    char dvpt_key[1024];
    int set_len = 0;
    int curr_testnumber= sentinal->testnumber; //grab the current test number

    unsigned char * h_key;
    long hex_keylen, hex_noncelen, hex_adatalen, hex_ciphertextlen,hex_payloadlen ;

    //Something has gone wrong, we should always be starting with a NULL
    if(sentinal->next!=NULL)
    {
        printf("Bad Book Keeping");
        exit(-1);
    }


    //read the entire file and parse out fields into the structure
    while(fgets(filestream, sizeof(filestream), vparse))
    {
        //Parse the Key
        if(strncmp(filestream, "Key =",5)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data); //Get the original size

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data)); //copy data from temporary pointer

            memset(sentinal->key,0,1024); //Clear
            strncpy(sentinal->key, data, dlen-3); //3 removes control characters...magic numbers
            memset(dvpt_key, 0, 1024);
            strncpy(dvpt_key, sentinal->key, strlen(sentinal->key)); //3 removes control characters...magic numbers
        }

        //Parse the Count
        if(strncmp(filestream, "Count =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");

            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));

            sentinal->count = atoi(data);
            sentinal->vectortest = vectortest; //tell us if fax or req
            sentinal->ciphertype= ciphersize; //128, 192, 256
            strncpy(sentinal->testtype, fname, strlen(fname)); //set its dvpt
        }

        //Grab the Alen, Plen, Nlen, Tlen
        if((strncmp(filestream, "[Alen =",7)==0) &&(!strncmp(fname, "DVPT", strlen(fname))))
        {
            //printf("*********************************\n");
            //printf("DVPT TEST\n");
            //printf("%s", filestream);
            //printf("*********************************\n");


            set_len = 0;
            data = strtok(filestream, ",");
            while(data !=NULL)
            {
                switch (set_len)
                {
                    case 0:
                        sentinal->alen = atoi(data+7);
                        dvpt_p_alen = sentinal->alen;
                        break;
                    case 1:
                        sentinal->plen = atoi(data+7);
                        dvpt_p_plen = sentinal->plen;
                        break;
                    case 2:
                        sentinal->nlen = atoi(data+7);
                        dvpt_p_nlen = sentinal->nlen;
                        break;
                    case 3:
                        sentinal->tlen = atoi(data+7);
                        dvpt_p_tlen = sentinal->tlen;
                        break;
                    default:
                        printf("Error Parsing");
                        exit(-1);
                }
                data = strtok(NULL,",");
                set_len++;
            }

        }
        
        //assign dvpt alen, plen, nlen, tlen
        if(((sentinal->count % 15) > 0) && (set_len > 0) && (!strncmp(fname, "DVPT", strlen(fname))))
            if(!strncmp(fname, "DVPT", strlen(fname)))
            {
                sentinal->alen = dvpt_p_alen;
                sentinal->plen = dvpt_p_plen;
                sentinal->nlen = dvpt_p_nlen;
                sentinal->tlen = dvpt_p_tlen;
                strncpy(sentinal->key,dvpt_key, strlen(dvpt_key)); //3 removes control characters...magic numbers

            }
        if(strncmp(filestream, "Nonce =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            dlen = strlen(data);
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->nonce, data, dlen-3);
        }

        if(strncmp(filestream, "Adata =",7)==0)
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->adata, data, strlen(data)-2);
        }
        if((strncmp(filestream, "CT =",4)==0) && (!strncmp(fname, "DVPT", strlen(fname))))
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->ct, data, strlen(data)-2);


            if(vectortest == 0)//If we are doing a fax file (1), then ignore this
            {
                //For DVPT CT is the last field so we allocate a new record
               /* printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Count =  %i\n", sentinal->count);
                printf("key = %s\n", sentinal->key);
                printf("nonce = %s\n", sentinal->nonce);
                printf("adata = %s\n", sentinal->adata);
                printf("CT = %s\n", sentinal->ct);
                printf("Cipher Size = %i\n", sentinal->ciphertype);

                printf("alen = %i\n", sentinal->alen);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                */
                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
            }
        }
        if(strncmp(filestream, "Result = Pass",13)==0 && (vectortest == 1))
        {
            sentinal->fax_result = 1; //0: fail 1: pass
        }
        
        if(strncmp(filestream, "Result = Fail",13)==0 && (vectortest == 1))
        {
                /*printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Count =  %i\n", sentinal->count);
                printf("key = %s\n", sentinal->key);
                printf("nonce = %s\n", sentinal->nonce);
                printf("adata = %s\n", sentinal->adata);
                printf("CT = %s\n", sentinal->ct);
                printf("Cipher Size = %i\n", sentinal->ciphertype);

                printf("alen = %i\n", sentinal->alen);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("Result = FAIL\n");
                */
                sentinal->fax_result = 0; //0: fail 1: pass  
                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
        }
        if(strncmp(filestream, "Payload =",9)==0 && (vectortest == 1) && (sentinal->fax_result == 1))
        {
            data = strtok(filestream, "=");
            data = strtok(NULL,"=");
            if(data[0] == ' ')
                memmove(data, data+1, strlen(data));
            strncpy(sentinal->fax_payload, data, strlen(data)-2);
                
            /*printf("************************\n");
                printf("************************\n");
                printf("Test Number ->%i\n", sentinal->testnumber);
                printf("Vector Test = %i\n", sentinal->vectortest);
                printf("Test Type = %s\n", sentinal->testtype);
                printf("Count =  %i\n", sentinal->count);
                printf("key = %s\n", sentinal->key);
                printf("nonce = %s\n", sentinal->nonce);
                printf("adata = %s\n", sentinal->adata);
                printf("CT = %s\n", sentinal->ct);
                printf("Cipher Size = %i\n", sentinal->ciphertype);

                printf("alen = %i\n", sentinal->alen);
                printf("plen = %i\n", sentinal->plen);
                printf("nlen = %i\n", sentinal->nlen);
                printf("tlen = %i\n", sentinal->tlen);
                printf("Result = Pass\n");
                printf("Payload = %s\n", sentinal->fax_payload);*/
                sentinal->next = (struct vectors*)malloc(sizeof(struct vectors));
                sentinal = sentinal->next;
                sentinal->next= NULL; //set the nullbit
                curr_testnumber +=1;
                sentinal->testnumber = curr_testnumber;
        }
    }

    return sentinal;
}
    
//This will be for VADT, VNT, VPT, VTT tests
int vector_encrypt(struct vectors* sentinal)
{
    long hex_keylen, hex_noncelen, hex_adatalen, hex_ciphertextlen,hex_payloadlen ;
    unsigned char * h_key;
    unsigned char * h_nonce;
    unsigned char * h_adata;
    unsigned char * h_ciphertext;
    unsigned char * h_payload;

    printf("\n+=========================================+\n");
    //printf("\n+==================================================+\n");
    printf("============= Test Number: %i =============\n", sentinal->testnumber);
    //printf("=====%s======= Test Number: %i === Count: %i ==========\n", sentinal->testtype, sentinal->testnumber, sentinal->count);
    printf("Test Type: %s\n", sentinal->testtype);
    printf("Cipher Type: %i\n", sentinal->ciphertype);
    printf("Count: %i\n", sentinal->count);

    printf("Key = %s\n", sentinal->key);
    printf("Nonce = %s\n", sentinal->nonce);
    printf("Adata = %s\n", sentinal->adata);
    //printf("Fax or Req = %i\n", sentinal->vectortest);
    if(sentinal->vectortest == 1) //if we're doing a Fax
        printf("CT = %s\n", sentinal->ct);

    printf("alen = %i\n", sentinal->alen);
    printf("plen = %i\n", sentinal->plen);
    printf("nlen = %i\n", sentinal->nlen);
    printf("tlen = %i\n", sentinal->tlen);

    h_key = OPENSSL_hexstr2buf(sentinal->key, &hex_keylen);
    //printf("Hex Key\n");
    //BIO_dump_fp(stdout, h_key, hex_keylen);
    h_nonce= OPENSSL_hexstr2buf(sentinal->nonce, &hex_noncelen);
    //printf("Hex Nonce\n");
    //BIO_dump_fp(stdout, h_nonce, hex_noncelen);
    h_adata= OPENSSL_hexstr2buf(sentinal->adata, &hex_adatalen);
    //printf("Hex Adata\n");
    //BIO_dump_fp(stdout, h_adata, hex_adatalen);
    if(sentinal->vectortest == 1) //if we're doing a Fax
    {
        h_ciphertext= OPENSSL_hexstr2buf(sentinal->ct, &hex_ciphertextlen);
        //printf("Hex CipherText\n");
        printf("Fax Ciphertext Hex\n");
        BIO_dump_fp(stdout, h_ciphertext, hex_ciphertextlen);
        printf("\n\n");
    }
    h_payload= OPENSSL_hexstr2buf(sentinal->payload, &hex_payloadlen);
    printf("Payload\n");
    BIO_dump_fp(stdout, h_payload, hex_payloadlen);
    printf("\n\n");

    /////
    /////
    /////
    /////
    /////
    /////
    int outlen, tmplen;
    unsigned char outbuf[1024];
    unsigned char ct_final[1024];
    unsigned char nct_final[1024];
    unsigned char tag_final[1024];
    unsigned char ntag_final[1024];
    memset(outbuf,0,1024);
    memset(ct_final,0,1024);
    memset(nct_final,0,1024);
    memset(tag_final,0,1024);
    memset(ntag_final,0,1024);
    EVP_CIPHER_CTX *ctx; 
    ctx = EVP_CIPHER_CTX_new();
    switch(sentinal->ciphertype)
    {
        case 128:
            EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
            break;
        case 192:
            EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
            break;
        case 256:
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
            break;
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sentinal->nlen, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sentinal->tlen, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, h_key, h_nonce);
    EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, sentinal->plen);
    EVP_EncryptUpdate(ctx, NULL, &outlen, h_adata, sentinal->alen);
    EVP_EncryptUpdate(ctx, outbuf, &outlen, h_payload, sentinal->plen);

    printf("Computed CipherText:\n");
    BIO_dump_fp(stdout,outbuf,outlen); //dump ciphertext to stdout by length of ct
    //EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    
   
    //This is where it breaks in part two
    //This is where it breaks in part two
    //This is where it breaks in part two
    
    //strncpy(ct_final, outbuf, strlen(outbuf));
    //
    
    printf("VALUES:\n");
    char * blah;
    //strlen breaks on NULL...tlen * 2? + 
    //
    //FIND OUT HOW TO SET THIS
    //FIND OUT HOW TO SET THIS
    //FIND OUT HOW TO SET THIS
    blah = OPENSSL_buf2hexstr(outbuf,32);
    strncpy(ct_final, blah, strlen(blah));
    printf(">>>>>>>>>>>>>>>>%s\n", blah);
    printf("\n");
    
    //for(int i=0; i < 100; i++)
    int i = 0;
    int kay = 0;
    int vpt_calc = 0;
    while(ct_final[i] != NULL)
    {
        //if(strrchr(ct_final[i],':'
        if(ct_final[i]!=':')
        {
            if(!strncmp(sentinal->testtype, "VPT", strlen(sentinal->testtype)))
            {
                if(vpt_calc == (sentinal->plen)*2)
                { 
                    break;
                }else
                {
                    vpt_calc++;
                }
            }
            nct_final[kay] = tolower(ct_final[i]);
            printf("%c", tolower(ct_final[i]));
            //printf("[%c]", blah[i]);
            kay++;
        }
        i++;

    }
    printf("---------------\n");
    printf("\n");
    printf("kayyy: %s\n", nct_final);


    /* Get tag */
    memset(outbuf,0,1024);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sentinal->tlen, outbuf);
    printf("Computed Tag:\n");
    BIO_dump_fp(stdout,outbuf,sentinal->tlen); //dump ciphertext to stdout by length of ct
    printf("\n\n");
    //printf("ct_final--->%s\n", ct_final);
    //printf("ciphertext--->%s\n", sentinal->ciphertext);
   
    ///
   
    /////
    //This is where it breaks in part two
    //This is where it breaks in part two
    //This is where it breaks in part two
    //This is where it breaks in part two
    //strcat(ct_final,outbuf);//breakig on NULL 0x00
    //
    //for(int i = 0; i < 32; i++)
    blah = OPENSSL_buf2hexstr(outbuf,sentinal->tlen);
    strncpy(tag_final, blah, strlen(blah));
    printf(">>>>>>>>>>>>>>>>%s\n", blah);
    printf("\n");
    
    //for(int i=0; i < 100; i++)
    printf("THE FINAL TAG :::::\n");
    i = 0;
    kay = 0;
    while(tag_final[i] != NULL)
    {
        //if(strrchr(ct_final[i],':'
        if(tag_final[i]!=':')
        {
            ntag_final[kay] = tolower(tag_final[i]);
            printf("%c", tolower(tag_final[i]));
            //printf("[%c]", blah[i]);
            kay++;
        }
        i++;

    }
    printf("---------------\n");
    printf("\n");
    printf("\n");

    strcat(nct_final, ntag_final);
    

            
    
    printf("The Output which keeps breaking\n");
    BIO_dump_fp(stdout, ct_final, strlen(ct_final)); //dump tag out to 

    printf("FAX Given::\n");
    BIO_dump_fp(stdout, h_ciphertext, strlen(h_ciphertext)); //dump tag out to 

    if(sentinal->vectortest == 0)
    {
        strncpy(sentinal->ct, nct_final, strlen(nct_final));
    }


    if(sentinal->vectortest == 1)
    {
        printf("THIS IS WHAT WE HAVE NON HEX::\n %s\n", sentinal->ct);
        printf("THIS IS WHAT WE HAVE Concat::\n %s\n", nct_final);
        
        if(strncmp(sentinal->ct,nct_final,strlen(nct_final))==0)
        {
            printf("Ciphers Match77\n");
        }else
        {
            printf("FAIL\n");
        }
    }
    //printf("%s", outbuf);
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outbuf, sentinal->tlen); //dump tag out to 
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

//This will be only for DVPT tests
int vector_decrypt(struct vectors* sentinal)
{
    long hex_keylen, hex_noncelen, hex_adatalen, hex_ciphertextlen,hex_payloadlen ;
    unsigned char * h_key;
    unsigned char * h_nonce;
    unsigned char * h_adata;
    unsigned char * h_ciphertext;
    unsigned char * h_payload;

    //printf("\n+=========================================+\n");
    printf("\n+==================================================+\n");
    //printf("============= Test Number: %i =============\n", sentinal->testnumber);
    printf("=====%s======= Test Number: %i === Count: %i ==========\n", sentinal->testtype, sentinal->testnumber, sentinal->count);
    //printf("Test Type: %s\n", sentinal->testtype);
    //printf("Cipher Type: %i\n", sentinal->ciphertype);
    //printf("Count: %i\n", sentinal->count);
    /*
    printf("Key = %s\n", sentinal->key);
    printf("Nonce = %s\n", sentinal->nonce);
    printf("Adata = %s\n", sentinal->adata);
    printf("CT = %s\n", sentinal->ct);

    printf("alen = %i\n", sentinal->alen);
    printf("plen = %i\n", sentinal->plen);
    printf("nlen = %i\n", sentinal->nlen);
    printf("tlen = %i\n", sentinal->tlen);
    */

    h_key = OPENSSL_hexstr2buf(sentinal->key, &hex_keylen);
    //printf("Hex Key\n");
    //BIO_dump_fp(stdout, h_key, hex_keylen);
    h_nonce= OPENSSL_hexstr2buf(sentinal->nonce, &hex_noncelen);
    //printf("Hex Nonce\n");
    //BIO_dump_fp(stdout, h_nonce, hex_noncelen);
    h_adata= OPENSSL_hexstr2buf(sentinal->adata, &hex_adatalen);
    //printf("Hex Adata\n");
    //BIO_dump_fp(stdout, h_adata, hex_adatalen);
    h_ciphertext= OPENSSL_hexstr2buf(sentinal->ct, &hex_ciphertextlen);
    //printf("Hex CipherText\n");
    //BIO_dump_fp(stdout, h_ciphertext, hex_ciphertextlen);

    if(sentinal->fax_result == 1) //we only have payload when things work
    {
        // printf("broken payload:%s\n", sentinal->fax_payload);
        h_payload= OPENSSL_hexstr2buf(sentinal->fax_payload, &hex_payloadlen);
        printf("Hex Fax Payload\n");
        BIO_dump_fp(stdout, h_payload, hex_payloadlen);
    }else
    {
        printf("No Payload\n");
    }

    int len, rv, plaintext_len;
    unsigned char plaintext[1024];
    memset(plaintext,0,1024);
    unsigned char tag[1024];
    memset(tag,0,1024);
    EVP_CIPHER_CTX *ctx; 
    ctx = EVP_CIPHER_CTX_new();

    switch(sentinal->ciphertype)
    {
        case 128:
            EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
            break;
        case 192:
            EVP_DecryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
            break;
        case 256:
            EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
            break;
    }


    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sentinal->nlen, NULL))
    {
        printf("FAIL");
        exit(-1);
    }

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, sentinal->tlen, h_ciphertext + sentinal->plen))
    {
        printf("FAIL");
        exit(-1);
    }

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, h_key, h_nonce))
    {
        printf("FAIL");
        exit(-1);
    }

    len = sentinal->plen;

    if(!EVP_DecryptUpdate(ctx, NULL, &len, NULL, sentinal->plen))
    {
        printf("FAIL");
        exit(-1);
    }

    if(!EVP_DecryptUpdate(ctx, NULL, &len, h_adata, sentinal->alen))
    {
        printf("FAIL");
        exit(-1);
    }

    rv = EVP_DecryptUpdate(ctx, plaintext, &len, h_ciphertext, sentinal->plen);

    plaintext_len = len;

    // Clean up 
    EVP_CIPHER_CTX_free(ctx);
    char * blah;

    if(rv > 0) {
        sentinal->result = 1;
        // Success //
        printf("*********************\n");
        printf("Payload PASS\n");
        //printf("PAYLOAD ------>\n");
        //BIO_dump_fp(stdout, plaintext, sentinal->plen);
        ///////////////
        char npayload_final[1024];
        memset(npayload_final,0,1024);
        int i = 0;
        int kay = 0;

    blah = OPENSSL_buf2hexstr(plaintext,sentinal->plen);
    //if(strncmp(blah,"\0\0",sentinal->plen))a
    if(blah[0] == NULL)
    {
        printf("GATO NULL: \n");
        //strncpy(sentinal->payload,"AA", sentinal->plen);
        sentinal->payload[0] = '0';
        sentinal->payload[1] = '0';
    }
    else
    {
        printf("GATO FULL: \n");

        while(blah[i] != NULL)
        {
            //if(strrchr(ct_final[i],':'
            if(blah[i]!=':')
            {
                npayload_final[kay] = tolower(blah[i]);
                printf("%c", tolower(blah[i]));
                kay++;
            }
            i++;

        }
        strncpy(sentinal->payload,npayload_final, strlen(npayload_final));
        printf("---------------\n");


    }

///////////////
        //strncpy(sentinal->payload, plaintext, sentinal->plen);
        //BIO_dump_fp(stdout, sentinal->payload, sentinal->plen);
        //printf("The payload is now: %s\n", sentinal->payload);
        printf("The payload is now: %s\n", sentinal->payload);

        //fax check use the stored values
        
            if(strncmp(sentinal->payload,sentinal->fax_payload,strlen(sentinal->fax_payload))==0)
            {
                printf("Payload Match");
            }else
            {
                printf("BAD!!! Final Payload doesn't match");
                exit(-1);
            }
        
        printf("*********************\n");


        if(sentinal->vectortest == 1 && sentinal->fax_result != sentinal->result)
        {
            //If we're doing a fax test and the fax result doesnt match the actual result, quit
            printf("*********************\n");
            printf("BAD::::Fax for Count: %i doesnt match results, Should Fail\n", sentinal->count);
            printf("*********************\n");
            exit(-1);
        }

        //if(strncmp(sentinal->fax_payload,plaintext,strlen(plaintext))==0)
        if (sentinal->vectortest == 1)
        {
            if(strncmp(h_payload,plaintext,strlen(plaintext))==0)
            {
                printf("Payload Match");
            }else
            {
                printf("BAD!!! Final Payload doesn't match");
                exit(-1);
            }
        }

    } else {
        sentinal->result = 0;
        printf("*********************\n");
        printf("Could Not Compute the Payload, abort\n");
        printf("*********************\n");
        
        //If we're doing a fax test and the fax result doesnt match the actual result, quit
        if(sentinal->vectortest == 1 && sentinal->fax_result != sentinal->result)
        {
            printf("*********************\n");
            printf("BAD::::Fax for Count: %i doesnt match results, Should Pass\n", sentinal->count);
            printf("*********************\n");
            //exit(-1);
        }
    }
            //printf("\n-=========================================-\n");
    printf("\n-==================================================-\n");


    return 0;
}

//This will write the appropriate response files
int vector_response(struct vectors* sentinal)
{
    char  ccm_resp_dir[]= "./Leidos_Vectors/CCM/resp/";
    
    while(sentinal->next != NULL)
    { 
        if(!(strncmp(sentinal->testtype,"DVPT", 4)))
        {
            sentinal = vector_resp_dvpt(sentinal);
        }
        if(!(strncmp(sentinal->testtype,"VADT", 4)))
        {
            sentinal = vector_resp_vadt(sentinal);
        }
        if(!(strncmp(sentinal->testtype,"VNT", 3)))
        {
            sentinal = vector_resp_vnt(sentinal);
        }
        
        if(!(strncmp(sentinal->testtype,"VPT", 3)))
        {
            sentinal = vector_resp_vpt(sentinal);
        }
        if(!(strncmp(sentinal->testtype,"VTT", 3)))
        {
            sentinal = vector_resp_vtt(sentinal);
        }
        sentinal = sentinal->next;
    }

    return 0;
}


int main(int argc, char *argv[]) 
{
    int vectortest = 0; //0:Req 1: Fax
    char vectortestext[4];
    
    char  ccm_dir[1024];
    memset(ccm_dir,0,1024);

    char  ccm_fax_dir[]= "./Leidos_Vectors/CCM/fax/";
    char  ccm_req_dir[]= "./Leidos_Vectors/CCM/req/";

    switch (vectortest)
                {
                    case 0: //we are doing a requests file
                        strncpy(vectortestext,".req",strlen(vectortestext));
                        strncpy(ccm_dir,ccm_req_dir, strlen(ccm_req_dir));
                        break;
                    case 1: //we are doing a fax file
                        strncpy(vectortestext,".fax",strlen(vectortestext));
                        strncpy(ccm_dir,ccm_fax_dir, strlen(ccm_req_dir));
                        break;
                }


    char fbuff[1024];
    char nbuff[20];//name_buffer
    char cbuff[20];//cipher_type
    struct dirent* de;
    
    
    DIR *dr = opendir(ccm_dir);
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
            strncpy(fbuff,ccm_dir,sizeof(ccm_dir));
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
            //printf("Name Buffer: %s \n",nbuff);
            //printf("Cipher Size: %i \n",atoi(cbuff));
            //strtok(de->d_name, ".");
            //vector_parse(sentinal, VectorFile, de->d_name);
            //grab the address of the last structure
            
            //Parse the DVPT 128, 192, 256 file

            if(!strncmp(nbuff, "DVPT", strlen(nbuff)))
            {
                printf("Type is: %s at %i\n", nbuff,atoi(cbuff));
                sentinal = dvpt_vector_parse(sentinal, VectorFile, nbuff, atoi(cbuff), vectortest);
            } 
            if(!strncmp(nbuff, "VADT", strlen(nbuff)))
            {
                printf("Type is: %s at %i\n", nbuff,atoi(cbuff));
                sentinal = vadt_vector_parse(sentinal, VectorFile, nbuff, atoi(cbuff), vectortest);
            } 
            if(!strncmp(nbuff, "VNT", strlen(nbuff)))
            {
                printf("Type is: %s at %i\n", nbuff,atoi(cbuff));
                sentinal = vnt_vector_parse(sentinal, VectorFile, nbuff, atoi(cbuff), vectortest);
            }
            if(!strncmp(nbuff, "VPT", strlen(nbuff)))
            {
                printf("Type is: %s at %i\n", nbuff,atoi(cbuff));
                sentinal = vpt_vector_parse(sentinal, VectorFile, nbuff, atoi(cbuff), vectortest);
            } 
            if(!strncmp(nbuff, "VTT", strlen(nbuff)))
            {
                printf("Type is: %s at %i\n", nbuff,atoi(cbuff));
                sentinal = vtt_vector_parse(sentinal, VectorFile, nbuff, atoi(cbuff), vectortest);
            } 
        }
    }
    
    closedir(dr);

    //We've already parsed, lets encrypt! or Decrypt
    sentinal = head; 

    while(sentinal->next != NULL)
    { 
        if(!(strncmp(sentinal->testtype,"DVPT", 4)))
        {
            vector_decrypt(sentinal);
        }
        if(!(strncmp(sentinal->testtype,"VADT", 4)))
        {
            vector_encrypt(sentinal);
        }
        if(!(strncmp(sentinal->testtype,"VNT", 3)))
        {
            vector_encrypt(sentinal);
        }
        if(!(strncmp(sentinal->testtype,"VPT", 3)))
        {
            vector_encrypt(sentinal);
        }
        if(!(strncmp(sentinal->testtype,"VTT", 3)))
        {
            vector_encrypt(sentinal);
        }
        sentinal = sentinal->next;
    }

    //Lets write the final
    sentinal = head;
    vector_response(sentinal);
    
}
