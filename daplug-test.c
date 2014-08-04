#include <stdio.h>
#include <stdlib.h>
#include <daplug/keyboard.h>
#include <daplug/DaplugDongle.h>

#define TRUE 1
#define FALSE 0

DaplugDongle *card, *sam;

extern FILE *flog_apdu;

Keyset keyset01, 
       hmacSha1Keyset;

int testHmacSha1(DaplugDongle *dpdCard){

    if(!Daplug_authenticate(dpdCard, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    if(!Daplug_putKey(dpdCard, hmacSha1Keyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\n+TEST: Hmac - sha1");

    int options;
        //use1div = OTP_1_DIV,
        //use2div = OTP_2_DIV;

    //options = use2div;
    options = OTP_0_DIV;

    char arbitraryData[MAX_REAL_DATA_SIZE*2+1]="01234587",//"012548deac475c5e478fde001111111144dddddddfea09999999999995",
         ret[MAX_REAL_DATA_SIZE*2+1]="";

    fprintf(stderr, "\nkey version:%d\n", hmacSha1Keyset.version);

    if(!Daplug_hmac(dpdCard, hmacSha1Keyset.version,options,NULL,NULL,arbitraryData,ret)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nArbitrary data : %s",arbitraryData);
   
    fprintf(stderr,"\nSignature on 20 bytes: %s\n",ret);

    fprintf(stderr, "\n************************************************************");
    fprintf(stderr, "\n********** \"testHmacSha1\" terminated with success **********\n");
    fprintf(stderr, "************************************************************\n");

    return 1;

}

int testGetSerial(DaplugDongle *dpdCard){

    fprintf(stderr,"\n+TEST : GET SERIAL");
    char sn[18*2+1]="";
    if(!Daplug_getDongleSerial(dpdCard, sn)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    fprintf(stderr,"\nSN = %s\n",sn);

    fprintf(stderr, "\n**********************************************************");
    fprintf(stderr, "\n********** \"testGetSerial\" terminated with success *******\n");
    fprintf(stderr, "**********************************************************\n");

    return 1;
}

int testGetStatus(DaplugDongle *dpdCard){

    int s = 0;
    char* status = "";
    fprintf(stderr,"\n+TEST : GET STATUS");
    if(!Daplug_getDongleStatus(dpdCard, &s)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
    switch(s){
        case 0x0F:
            status = "PERSONALIZED";
            break;
        case 0x7F:
            status = "TERMINATED";
            break;
        case 0x83:
            status = "LOCKED";
            break;
    }

    fprintf(stderr,"\nstatus = %s\n",status);

    fprintf(stderr, "\n**********************************************************");
    fprintf(stderr, "\n********** \"testGetStatus\" terminated with success *******\n");
    fprintf(stderr, "**********************************************************\n");

    return 1;
}

int main()
{

    //=====================================================================================================

    //keyset 01 - GP Keyset (used for authentication)
    if(!keyset_createKeys(&keyset01, 0x01,"404142434445464748494a4b4c4d4e4f",NULL,NULL)){
        return 0;
    }

    //Keysets to create
    /*
    expected : a new keyset id & three gp keys.
    Possible "usage" to use are present in the "keyset.h" file..
    access value 1 =  time src key version if TOTP key, if other key, key version of a keyset wich protect the access to
    the new created keyset (0x01 to 0x0F), or 0x00 for always access.
    access value 2 = min security level if GP key ; key length if hmac-sha1/hotp/hotp-validation/totp/totp-validation key ;
    or decryption access if encrypt/decrypt key.
    For more details, refer to the product specification, section "put key".
    */
    //
    //Clean card

    
    //Hmac-sha1 keyset
    if(!keyset_createKeys(&hmacSha1Keyset, 0x54, 
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "0b0b0b0b000000000000000000000000",
      "00000000000000000000000000000000"
      )){
        return 0;
    }
    hmacSha1Keyset.usage = USAGE_HMAC_SHA1;
    int access4[] = {ACCESS_ALWAYS, 48};
    if(!keyset_setKeyAccess(&hmacSha1Keyset,access4)){
        return 0;
    }

    //============================================= Log ================================================

    //open log file for exchanged apdus
    flog_apdu = fopen("apdu_log.txt","w");

    //=================================== Enumerating then selecting dongle ============================

    /*
    If you want test SAM functions, we assume that you have a card and a sam connected;
    that the card is the first detected (id 0) and the SAM is the second detected (id 1)
    If you want do tests only on card (without using SAM), just comment code corresponding to tests functions using SAM.
    */

    char **donglesList = NULL;
    int nbDongles = Daplug_getDonglesList(&donglesList);

    if(nbDongles > 0){
        fprintf(stdout,"\n+Connected dongles:\n");
    }else{
        return 0;
    }

    int i;
    for(i=0;i<nbDongles;i++){
        fprintf(stderr, "\n%s", donglesList[i]);
    }

    fprintf(stderr, "\n\nget card on %s...", donglesList[0]);
    if((card = Daplug_getDongleById(0)) == NULL){
        return 0;
    }else{
        fprintf(stderr, "\nOk.\n");
    }

    //===================================== Authentication =============================================
    /*
    expected : security level (1 = Command integrity (the default, mandatory), 2 = Command data encryption
                                 3 = Response integrity, 4 = Response data encryption
                                 5 = 1 & 2 & 3 , 6 = 1 & 2 & 4 , 7 = 1 & 3 & 4
                                 8 = 1 & 2 & 3 & 4 , All other values = Command integrity  */

    testGetSerial(card);

    testGetStatus(card);

/*    if(!Daplug_deleteKey(card, 0x54)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }
*/
    testHmacSha1(card);

    if(card) Daplug_close(card);
    if(sam) Daplug_close(sam);


    if(donglesList) Daplug_exit(&donglesList);
    fclose(flog_apdu);

    return 1;
}
