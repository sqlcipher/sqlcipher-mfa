#include <sqlite3.c>
#include <src/sqlcipher.h>
#include <stdio.h>

#define ERROR(X)  {printf("[ERROR]: ");printf X;fflush(stdout);}

#include <yubikey.h>
#include <ykpers.h>
#include <ykdef.h>

#include <daplug/DaplugDongle.h>

static int diversify_yubikey(void *ctx, unsigned char *in, int in_sz, unsigned char *out){
  YK_KEY *yk;
  int versionMajor;
  int versionMinor;
  int versionBuild;
  int slot = 2;
  int yk_cmd = (slot == 1) ? SLOT_CHAL_HMAC1 : SLOT_CHAL_HMAC2;
  YK_STATUS *st = ykds_alloc(); 
	unsigned int response_len = 0;
  unsigned char *data;
  int offset;
  unsigned int hmac_bytes = 20;
	unsigned int expect_bytes = hmac_bytes;
  unsigned char buffer[20];
  unsigned char response[64];
  int i = 0;
  char challenge[MAX_REAL_DATA_SIZE*2+1],
       ret[MAX_REAL_DATA_SIZE*2+1];

  versionMajor = versionMinor = versionBuild = 0;
  yk_errno = 0;

  fprintf(stdout,"diversify_yubikey()\n");

  if (yk_init() && (yk = yk_open_first_key())) {
    if (!yk_get_status(yk, st)) {
      ERROR(("Unable to get status from Yubikey: error %d (%s)\n", yk_errno, yk_strerror(yk_errno)));
      return SQLITE_ERROR;
    } else {
      versionMajor = ykds_version_major(st);
      versionMinor = ykds_version_minor(st);
      versionBuild = ykds_version_build(st); 
      if (versionMajor < 2 || (versionMajor == 2 && versionMinor < 2)) {
        ERROR(("Incorrect firmware version: HMAC challenge-response not supported with YubiKey %d.%d.%d\n", 
                        versionMajor, versionMinor, versionBuild));
        return SQLITE_ERROR;
      }
    }
       
    for(i = 0, offset = 0; offset < in_sz; i++) {
      int block_sz;
      data = in + offset;
      block_sz = (hmac_bytes < in_sz - offset) ? hmac_bytes : in_sz - offset;
      memset(buffer, 1, hmac_bytes);
      memcpy(buffer, data, block_sz);
      memset(challenge, 0, MAX_REAL_DATA_SIZE*2+1);
      memset(ret, 0, MAX_REAL_DATA_SIZE*2+1);

      cipher_bin2hex(buffer, hmac_bytes, challenge);

      fprintf(stdout, "iteration %d: challenge to yubikey in_sz=%d, offset=%d, block_sz=%d, challenge=%s\n", i, in_sz, offset, block_sz, challenge);

      /* issue HMAC challenge */
  	  if (!yk_write_to_key(yk, yk_cmd, buffer, hmac_bytes)) {
  	  //if (!yk_write_to_key(yk, yk_cmd, buffer, 12)) {
        ERROR(("Error writing HMAC challenge to Yubikey\n"));
        return SQLITE_ERROR;
      }
      if (!yk_read_response_from_key(
            yk, slot, YK_FLAG_MAYBLOCK, // use selected slot and allow the yubikey to block for button press
            &response, sizeof(response), hmac_bytes, &response_len)) {
        ERROR(("error reading HMAC response from Yubikey: code %d (%s)\n", yk_errno, yk_strerror(yk_errno)));
        return SQLITE_ERROR;
      } else {
        /* HMAC responses are 160 bits */
        cipher_bin2hex(response, hmac_bytes, ret);
        fprintf(stdout, "received response from Yubikey:  %s\n", ret);
        memcpy(out + offset, response, block_sz); /* only copy a blocks worth of of response */
      }
      offset += block_sz;
    }
  } else {
    ERROR(("Unable to open Yubikey: code %d (%s)\n", yk_errno, yk_strerror(yk_errno)));
    return SQLITE_ERROR;
  }

  return SQLITE_OK;
}

static int diversify_daplug(void *ctx, unsigned char *in, int in_sz, unsigned char *out){
	unsigned int response_len = 0;
  unsigned char *data;
  int offset;
  unsigned int hmac_bytes = 20;
	unsigned int expect_bytes = hmac_bytes;
  unsigned char buffer[20];
  unsigned char response[64];
  int i = 0;
  char challenge[MAX_REAL_DATA_SIZE*2+1],
       ret[MAX_REAL_DATA_SIZE*2+1];
  DaplugDongle *card;

  char **donglesList = NULL;
  int nbDongles = Daplug_getDonglesList(&donglesList);
  
  fprintf(stdout,"diversify_daplug()\n");
  card = Daplug_getDongleById(0);

  for(i = 0, offset = 0; offset < in_sz; i++) {
    int block_sz;
    data = in + offset;
    block_sz = (hmac_bytes < in_sz - offset) ? hmac_bytes : in_sz - offset;
    memset(buffer, 1, hmac_bytes);
    memset(challenge, 0, MAX_REAL_DATA_SIZE*2+1);
    memset(ret, 0, MAX_REAL_DATA_SIZE*2+1);
    memcpy(buffer, data, block_sz);

    cipher_bin2hex(buffer, hmac_bytes, challenge);

    fprintf(stdout, "iteration %d: challenge to daplug in_sz=%d, offset=%d, block_sz=%d challenge=%s\n", i, in_sz, offset, block_sz, challenge);

    if(!Daplug_hmac(card,0x54,OTP_0_DIV,NULL,NULL,challenge,ret)) {
      ERROR(("Error writing HMAC challenge to daplug\n"));
      return SQLITE_ERROR;
    } else {
      cipher_hex2bin((const unsigned char*) ret, hmac_bytes * 2, response);
      memcpy(out + offset, response, block_sz); /* only copy one blocks worth */
    }
    offset += block_sz;
  }

  Daplug_close(card);
  return SQLITE_OK;
}


int main(int argc, char **argv) {
  sqlite3 *db;
  const char *file= "sqlcipher.db";
  char* key = (char *) "test123";
  unsigned long inserts = 0;
  unsigned long insert_rows = 30;
  int rc, i;
  sqlcipher_provider *provider;
  int use_yubikey = -1;

  if(argc < 2) {
      fprintf(stderr, "specify -d or -y to use daplug or yuibkey respectively\n");
      exit(1);
  }

  for (i = 1; i < argc; i++) {
    if(strcmp(argv[i], "-y") == 0) {
      use_yubikey = 1;
    } else if (strcmp(argv[i], "-d") ==0) {
      use_yubikey = 0;
    } else {
    }
  }


   
  sqlcipher_register_provider(NULL);
  provider = sqlcipher_get_provider();

  if(use_yubikey) {
    provider->diversify = diversify_yubikey;
  } else {
    provider->diversify = diversify_daplug;
  }

  sqlcipher_register_provider(provider);

  srand(0);

  if (sqlite3_open(file, &db) == SQLITE_OK) {
    int row, rc, master_rows;
    sqlite3_stmt *stmt;

    if(sqlite3_key(db, key, strlen(key)) != SQLITE_OK) {
      ERROR(("error setting key %s\n", sqlite3_errmsg(db)))
      exit(1);
    }

    /* read schema. If no rows, create table and stuff
       if error - close it up!*/
    if(sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master;", -1, &stmt, NULL) == SQLITE_OK) {
      if (sqlite3_step(stmt) == SQLITE_ROW) {
        master_rows = sqlite3_column_int(stmt, 0);
      } else {
        ERROR(("error authenticating database %s\n", sqlite3_errmsg(db)))
        exit(1);
      }
    } else {
      ERROR(("error preparing sqlite_master query %s\n", sqlite3_errmsg(db)))
      exit(1);
    }
    sqlite3_finalize(stmt);
  
    if(master_rows == 0) { /* no schema yet */
      if(sqlite3_exec(db, "CREATE TABLE t1(a,b);", NULL, NULL, NULL) != SQLITE_OK) {
        ERROR(("error preparing sqlite_master query %s\n", sqlite3_errmsg(db)))
      }
      if(sqlite3_exec(db, "CREATE INDEX t1_a_idx ON t1(a);", NULL, NULL, NULL) != SQLITE_OK) {
        ERROR(("error creating index %s\n", sqlite3_errmsg(db)))
      }

  
      if(sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK) {
        ERROR(("error starting transaction %s\n", sqlite3_errmsg(db)))
      }
     
      if(sqlite3_prepare_v2(db, "INSERT INTO t1(a,b) VALUES (?, ?);", -1, &stmt, NULL) == SQLITE_OK) {
        for(row = 0; row < insert_rows; row++) {
          sqlite3_bind_int(stmt, 1, rand());
          sqlite3_bind_int(stmt, 2, rand());
          if (sqlite3_step(stmt) != SQLITE_DONE) {
            ERROR(("error inserting row %s\n", sqlite3_errmsg(db)))
            exit(1);
          }
          inserts++;
          sqlite3_reset(stmt);
        }
      } else {
        ERROR(("error preparing insert %s\n", sqlite3_errmsg(db)))
        exit(1);
      }
      sqlite3_finalize(stmt);

      if(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        ERROR(("error committing transaction %s\n", sqlite3_errmsg(db)))
      }
    } else {
      int a, b;
      if(sqlite3_prepare_v2(db, "SELECT * FROM t1;", -1, &stmt, NULL) == SQLITE_OK) {
        while((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
          a = sqlite3_column_int(stmt, 0);
          b = sqlite3_column_int(stmt, 1);
          printf("| %-10d | %-10d |\n", a, b);
        } 
      } else {
        ERROR(("error preparing sqlite_master query %s\n", sqlite3_errmsg(db)))
        exit(1);
      }
      sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
  } else {
    ERROR(("error opening database %s\n", sqlite3_errmsg(db)))
    exit(1);
  }	

  printf("completed test run\n");
}
