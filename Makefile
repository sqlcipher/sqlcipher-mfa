SQLITEDIR = ../sqlcipher
DAPLUGDIR = ../daplug-c

INCS = 
CFLAGS = \
	-g \
	-DSQLITE_TEMP_STORE=1 \
	-DSQLITE_HAS_CODEC \
	-DSQLITE_OS_UNIX=1 \
	-DSQLITE_THREADSAFE=1 \
	-DSQLCIPHER_CRYPTO_CC \
	-I$(SQLITEDIR) \
	-I$(DAPLUGDIR)/src/include \
	-I /usr/local/include \
	-I /usr/local/include/ykpers-1


LDFLAGS = \
	-lusb-1.0 \
	-lcrypto \
	/System/Library/Frameworks/CoreFoundation.framework/Versions/Current/CoreFoundation \
	/System/Library/Frameworks/IOKit.framework/Versions/Current/IOKit \
	/System/Library/Frameworks/Security.framework/Versions/Current/Security \
	/usr/local/lib/libyubikey.a \
	/usr/local/lib/libykpers-1.a

CC = clang

OTHER_SRC = \
	$(DAPLUGDIR)/src/winusb.c \
	$(DAPLUGDIR)/src/DaplugDongle.c \
	$(DAPLUGDIR)/src/apdu.c \
	$(DAPLUGDIR)/src/comm.c \
	$(DAPLUGDIR)/src/hidapi_osx.c \
	$(DAPLUGDIR)/src/keyboard.c \
	$(DAPLUGDIR)/src/keyset.c \
	$(DAPLUGDIR)/src/sam.c \
	$(DAPLUGDIR)/src/sc.c \
	$(DAPLUGDIR)/src/utils.c 

OBJS = ${SRC:.c=.o}

MFA_SRC = mfa.c 
MFA_TARGET = mfa

DFLASH_SRC = daplug-flash.c 
DFLASH_TARGET = daplug-flash

all: $(MFA_TARGET) $(DFLASH_TARGET)

$(MFA_TARGET): $(MFA_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OTHER_SRC) $(MFA_SRC) -o $@

$(DFLASH_TARGET): $(DFLASH_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OTHER_SRC) $(DFLASH_SRC) -o $@

clean:
	rm -rf $(OBJS) *.dSYM *.db $(MFA_TARGET) $(DFLASH_TARGET)
