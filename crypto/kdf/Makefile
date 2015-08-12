#
# OpenSSL/crypto/kdf/Makefile
#

DIR=	kdf
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=kdftest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= kdf_snmp.c kdf_err.c kdf_srtp.c kdf_ssh.c kdf_802_11i.c kdf_tls.c kdf_ikev2.c
LIBOBJ= kdf_snmp.o kdf_err.o kdf_srtp.o kdf_ssh.o kdf_802_11i.o kdf_tls.o kdf_ikev2.o

SRC= $(LIBSRC)

EXHEADER= kdf.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

# We need to use force because 'install' matches 'INSTALL' on case
# insensitive systems
FRC.install:
install: FRC.install
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

kdf_802_11i.o: ../../e_os.h ../../include/openssl/asn1.h
kdf_802_11i.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
kdf_802_11i.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
kdf_802_11i.o: ../../include/openssl/err.h ../../include/openssl/evp.h
kdf_802_11i.o: ../../include/openssl/hmac.h ../../include/openssl/kdf.h
kdf_802_11i.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
kdf_802_11i.o: ../../include/openssl/objects.h
kdf_802_11i.o: ../../include/openssl/opensslconf.h
kdf_802_11i.o: ../../include/openssl/opensslv.h
kdf_802_11i.o: ../../include/openssl/ossl_typ.h
kdf_802_11i.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
kdf_802_11i.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
kdf_802_11i.o: ../cryptlib.h kdf_802_11i.c
kdf_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
kdf_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
kdf_err.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
kdf_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
kdf_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
kdf_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
kdf_err.o: kdf_err.c
kdf_ikev2.o: ../../e_os.h ../../include/openssl/asn1.h
kdf_ikev2.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
kdf_ikev2.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
kdf_ikev2.o: ../../include/openssl/err.h ../../include/openssl/evp.h
kdf_ikev2.o: ../../include/openssl/hmac.h ../../include/openssl/kdf.h
kdf_ikev2.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
kdf_ikev2.o: ../../include/openssl/objects.h
kdf_ikev2.o: ../../include/openssl/opensslconf.h
kdf_ikev2.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kdf_ikev2.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
kdf_ikev2.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
kdf_ikev2.o: ../cryptlib.h kdf_ikev2.c
kdf_snmp.o: ../../e_os.h ../../include/openssl/asn1.h
kdf_snmp.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
kdf_snmp.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
kdf_snmp.o: ../../include/openssl/err.h ../../include/openssl/evp.h
kdf_snmp.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
kdf_snmp.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
kdf_snmp.o: ../../include/openssl/opensslconf.h
kdf_snmp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kdf_snmp.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
kdf_snmp.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
kdf_snmp.o: ../cryptlib.h kdf_snmp.c
kdf_srtp.o: ../../e_os.h ../../include/openssl/asn1.h
kdf_srtp.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
kdf_srtp.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
kdf_srtp.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
kdf_srtp.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
kdf_srtp.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
kdf_srtp.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
kdf_srtp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kdf_srtp.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
kdf_srtp.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
kdf_srtp.o: ../cryptlib.h kdf_srtp.c
kdf_ssh.o: ../../e_os.h ../../include/openssl/asn1.h
kdf_ssh.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
kdf_ssh.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
kdf_ssh.o: ../../include/openssl/err.h ../../include/openssl/evp.h
kdf_ssh.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
kdf_ssh.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
kdf_ssh.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
kdf_ssh.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
kdf_ssh.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
kdf_ssh.o: ../../include/openssl/symhacks.h ../cryptlib.h kdf_ssh.c
kdf_tls.o: ../../e_os.h ../../include/openssl/asn1.h
kdf_tls.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
kdf_tls.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
kdf_tls.o: ../../include/openssl/err.h ../../include/openssl/evp.h
kdf_tls.o: ../../include/openssl/hmac.h ../../include/openssl/kdf.h
kdf_tls.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
kdf_tls.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
kdf_tls.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kdf_tls.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
kdf_tls.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
kdf_tls.o: ../cryptlib.h kdf_tls.c
