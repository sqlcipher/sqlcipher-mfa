SQLITEDIR = ../sqlcipher

INCS = 
CFLAGS = -g \
	-DSQLITE_TEMP_STORE=1 -DSQLITE_HAS_CODEC -DSQLITE_OS_UNIX=1 -DSQLITE_THREADSAFE=1 \
	-DSQLCIPHER_CRYPTO_CC \
	-I$(SQLITEDIR) \
	-I /usr/local/include -I /usr/local/include/ykpers-1 \


LDFLAGS = /System/Library/Frameworks/CoreFoundation.framework/Versions/Current/CoreFoundation /System/Library/Frameworks/IOKit.framework/Versions/Current/IOKit /System/Library/Frameworks/Security.framework/Versions/Current/Security /usr/local/lib/libyubikey.a /usr/local/lib/libykpers-1.a

CC = clang

SRC = mfa.c 
OTHER_SRC = 
OBJS = ${SRC:.c=.o}
TARGET = mfa

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OTHER_SRC) $(SRC) -o $@

clean:
	rm -rf $(OBJS) *.dSYM *.db $(TARGET)
