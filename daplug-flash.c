#include <stdio.h>
#include <stdlib.h>
#include <daplug/keyboard.h>
#include <daplug/DaplugDongle.h>

int main()
{
    DaplugDongle *card;

    Keyset keyset01, hmacSha1Keyset; 
       
    // default keyset on card from factory
    if(!keyset_createKeys(&keyset01, 0x01,"404142434445464748494a4b4c4d4e4f",NULL,NULL)){
        return 0;
    }

    //Hmac-sha1 keyset
    if(!keyset_createKeys(&hmacSha1Keyset, 0x54, 
      "1b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
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

    if(!Daplug_authenticate(card, keyset01,C_MAC+C_DEC+R_MAC+R_ENC,NULL,NULL)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    if(!Daplug_putKey(card, hmacSha1Keyset, 0)){
        fprintf(stderr, "\n***** An error occured during the test ! *****\n");
        return 0;
    }

    if(card) Daplug_close(card);

    if(donglesList) Daplug_exit(&donglesList);

    return 1;
}
