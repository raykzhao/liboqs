ifeq (x64,$(ARCH))
ENABLE_KEMS+=$(findstring titanium_kmac_toy, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_toy, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_lite, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_lite, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_std, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_std, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_med, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_med, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_hi, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_hi, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_super, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_super, $(KEMS_TO_ENABLE))
MAKE_FLAGS_KEM_TITANIUM=
else ifeq (x86,$(ARCH))
ENABLE_KEMS+=$(findstring titanium_kmac_toy, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_toy, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_lite, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_lite, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_std, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_std, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_med, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_med, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_hi, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_hi, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_kmac_super, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_aes_super, $(KEMS_TO_ENABLE))
MAKE_FLAGS_KEM_TITANIUM=
endif

HEADERS_KEM_TITANIUM=src/kem/titanium/kem_titanium.h
HEADERS_KEM+=$(HEADERS_KEM_TITANIUM)

OBJECT_DIRS+=.objs/kem/titanium
OBJECTS_KEM_TITANIUM=.objs/kem/titanium/kem_titanium.o
OBJECTS_KEM+=$(OBJECTS_KEM_TITANIUM)

.objs/kem/titanium/kem_titanium.o: src/kem/titanium/kem_titanium.c
	$(CC) -c src/kem/titanium/kem_titanium.c -o .objs/kem/titanium/kem_titanium.o $(CFLAGS)

ARCHIVES_KEM_TITANIUM_KMAC_TOY=.objs/kem/titanium/kem_titanium_kmac_toy_upstream.a
ifneq (,$(findstring titanium_kmac_toy, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_KMAC_TOY)
endif
ARCHIVES_KEM_TITANIUM_AES_TOY=.objs/kem/titanium/kem_titanium_aes_toy_upstream.a
ifneq (,$(findstring titanium_aes_toy, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_AES_TOY)
endif

ARCHIVES_KEM_TITANIUM_KMAC_LITE=.objs/kem/titanium/kem_titanium_kmac_lite_upstream.a
ifneq (,$(findstring titanium_kmac_lite, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_KMAC_LITE)
endif
ARCHIVES_KEM_TITANIUM_AES_LITE=.objs/kem/titanium/kem_titanium_aes_lite_upstream.a
ifneq (,$(findstring titanium_aes_lite, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_AES_LITE)
endif

ARCHIVES_KEM_TITANIUM_KMAC_STD=.objs/kem/titanium/kem_titanium_kmac_std_upstream.a
ifneq (,$(findstring titanium_kmac_std, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_KMAC_STD)
endif
ARCHIVES_KEM_TITANIUM_AES_STD=.objs/kem/titanium/kem_titanium_aes_std_upstream.a
ifneq (,$(findstring titanium_aes_std, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_AES_STD)
endif

ARCHIVES_KEM_TITANIUM_KMAC_MED=.objs/kem/titanium/kem_titanium_kmac_med_upstream.a
ifneq (,$(findstring titanium_kmac_med, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_KMAC_MED)
endif
ARCHIVES_KEM_TITANIUM_AES_MED=.objs/kem/titanium/kem_titanium_aes_med_upstream.a
ifneq (,$(findstring titanium_aes_med, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_AES_MED)
endif

ARCHIVES_KEM_TITANIUM_KMAC_HI=.objs/kem/titanium/kem_titanium_kmac_hi_upstream.a
ifneq (,$(findstring titanium_kmac_hi, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_KMAC_HI)
endif
ARCHIVES_KEM_TITANIUM_AES_HI=.objs/kem/titanium/kem_titanium_aes_hi_upstream.a
ifneq (,$(findstring titanium_aes_hi, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_AES_HI)
endif

ARCHIVES_KEM_TITANIUM_KMAC_SUPER=.objs/kem/titanium/kem_titanium_kmac_super_upstream.a
ifneq (,$(findstring titanium_kmac_super, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_KMAC_SUPER)
endif
ARCHIVES_KEM_TITANIUM_AES_SUPER=.objs/kem/titanium/kem_titanium_aes_super_upstream.a
ifneq (,$(findstring titanium_aes_super, $(ENABLE_KEMS)))
ARCHIVES_KEM+=$(ARCHIVES_KEM_TITANIUM_AES_SUPER)
endif

.objs/kem/titanium/kem_titanium_kmac_toy_upstream.a:
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_toy && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/kmac/Titanium_CCA_toy/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_kmac_toy
	bash scripts/symbol_alias.sh $@ titanium_kmac_toy_crypto_kem_keypair OQS_KEM_titanium_kmac_toy_keypair
	bash scripts/symbol_alias.sh $@ titanium_kmac_toy_crypto_kem_enc OQS_KEM_titanium_kmac_toy_encaps
	bash scripts/symbol_alias.sh $@ titanium_kmac_toy_crypto_kem_dec OQS_KEM_titanium_kmac_toy_decaps
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_toy && $(MAKE) clean

.objs/kem/titanium/kem_titanium_aes_toy_upstream.a:
	cd src/kem/titanium/upstream/aes/Titanium_CCA_toy && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/aes/Titanium_CCA_toy/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_aes_toy
	bash scripts/symbol_alias.sh $@ titanium_aes_toy_crypto_kem_keypair OQS_KEM_titanium_aes_toy_keypair
	bash scripts/symbol_alias.sh $@ titanium_aes_toy_crypto_kem_enc OQS_KEM_titanium_aes_toy_encaps
	bash scripts/symbol_alias.sh $@ titanium_aes_toy_crypto_kem_dec OQS_KEM_titanium_aes_toy_decaps
	cd src/kem/titanium/upstream/aes/Titanium_CCA_toy && $(MAKE) clean

.objs/kem/titanium/kem_titanium_kmac_lite_upstream.a:
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_lite && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/kmac/Titanium_CCA_lite/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_kmac_lite
	bash scripts/symbol_alias.sh $@ titanium_kmac_lite_crypto_kem_keypair OQS_KEM_titanium_kmac_lite_keypair
	bash scripts/symbol_alias.sh $@ titanium_kmac_lite_crypto_kem_enc OQS_KEM_titanium_kmac_lite_encaps
	bash scripts/symbol_alias.sh $@ titanium_kmac_lite_crypto_kem_dec OQS_KEM_titanium_kmac_lite_decaps
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_lite && $(MAKE) clean

.objs/kem/titanium/kem_titanium_aes_lite_upstream.a:
	cd src/kem/titanium/upstream/aes/Titanium_CCA_lite && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/aes/Titanium_CCA_lite/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_aes_lite
	bash scripts/symbol_alias.sh $@ titanium_aes_lite_crypto_kem_keypair OQS_KEM_titanium_aes_lite_keypair
	bash scripts/symbol_alias.sh $@ titanium_aes_lite_crypto_kem_enc OQS_KEM_titanium_aes_lite_encaps
	bash scripts/symbol_alias.sh $@ titanium_aes_lite_crypto_kem_dec OQS_KEM_titanium_aes_lite_decaps
	cd src/kem/titanium/upstream/aes/Titanium_CCA_lite && $(MAKE) clean

.objs/kem/titanium/kem_titanium_kmac_std_upstream.a:
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_std && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/kmac/Titanium_CCA_std/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_kmac_std
	bash scripts/symbol_alias.sh $@ titanium_kmac_std_crypto_kem_keypair OQS_KEM_titanium_kmac_std_keypair
	bash scripts/symbol_alias.sh $@ titanium_kmac_std_crypto_kem_enc OQS_KEM_titanium_kmac_std_encaps
	bash scripts/symbol_alias.sh $@ titanium_kmac_std_crypto_kem_dec OQS_KEM_titanium_kmac_std_decaps
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_std && $(MAKE) clean

.objs/kem/titanium/kem_titanium_aes_std_upstream.a:
	cd src/kem/titanium/upstream/aes/Titanium_CCA_std && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/aes/Titanium_CCA_std/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_aes_std
	bash scripts/symbol_alias.sh $@ titanium_aes_std_crypto_kem_keypair OQS_KEM_titanium_aes_std_keypair
	bash scripts/symbol_alias.sh $@ titanium_aes_std_crypto_kem_enc OQS_KEM_titanium_aes_std_encaps
	bash scripts/symbol_alias.sh $@ titanium_aes_std_crypto_kem_dec OQS_KEM_titanium_aes_std_decaps
	cd src/kem/titanium/upstream/aes/Titanium_CCA_std && $(MAKE) clean

.objs/kem/titanium/kem_titanium_kmac_med_upstream.a:
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_med && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/kmac/Titanium_CCA_med/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_kmac_med
	bash scripts/symbol_alias.sh $@ titanium_kmac_med_crypto_kem_keypair OQS_KEM_titanium_kmac_med_keypair
	bash scripts/symbol_alias.sh $@ titanium_kmac_med_crypto_kem_enc OQS_KEM_titanium_kmac_med_encaps
	bash scripts/symbol_alias.sh $@ titanium_kmac_med_crypto_kem_dec OQS_KEM_titanium_kmac_med_decaps
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_med && $(MAKE) clean

.objs/kem/titanium/kem_titanium_aes_med_upstream.a:
	cd src/kem/titanium/upstream/aes/Titanium_CCA_med && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/aes/Titanium_CCA_med/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_aes_med
	bash scripts/symbol_alias.sh $@ titanium_aes_med_crypto_kem_keypair OQS_KEM_titanium_aes_med_keypair
	bash scripts/symbol_alias.sh $@ titanium_aes_med_crypto_kem_enc OQS_KEM_titanium_aes_med_encaps
	bash scripts/symbol_alias.sh $@ titanium_aes_med_crypto_kem_dec OQS_KEM_titanium_aes_med_decaps
	cd src/kem/titanium/upstream/aes/Titanium_CCA_med && $(MAKE) clean

.objs/kem/titanium/kem_titanium_kmac_hi_upstream.a:
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_hi && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/kmac/Titanium_CCA_hi/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_kmac_hi
	bash scripts/symbol_alias.sh $@ titanium_kmac_hi_crypto_kem_keypair OQS_KEM_titanium_kmac_hi_keypair
	bash scripts/symbol_alias.sh $@ titanium_kmac_hi_crypto_kem_enc OQS_KEM_titanium_kmac_hi_encaps
	bash scripts/symbol_alias.sh $@ titanium_kmac_hi_crypto_kem_dec OQS_KEM_titanium_kmac_hi_decaps
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_hi && $(MAKE) clean

.objs/kem/titanium/kem_titanium_aes_hi_upstream.a:
	cd src/kem/titanium/upstream/aes/Titanium_CCA_hi && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/aes/Titanium_CCA_hi/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_aes_hi
	bash scripts/symbol_alias.sh $@ titanium_aes_hi_crypto_kem_keypair OQS_KEM_titanium_aes_hi_keypair
	bash scripts/symbol_alias.sh $@ titanium_aes_hi_crypto_kem_enc OQS_KEM_titanium_aes_hi_encaps
	bash scripts/symbol_alias.sh $@ titanium_aes_hi_crypto_kem_dec OQS_KEM_titanium_aes_hi_decaps
	cd src/kem/titanium/upstream/aes/Titanium_CCA_hi && $(MAKE) clean

.objs/kem/titanium/kem_titanium_kmac_super_upstream.a:
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_super && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/kmac/Titanium_CCA_super/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_kmac_super
	bash scripts/symbol_alias.sh $@ titanium_kmac_super_crypto_kem_keypair OQS_KEM_titanium_kmac_super_keypair
	bash scripts/symbol_alias.sh $@ titanium_kmac_super_crypto_kem_enc OQS_KEM_titanium_kmac_super_encaps
	bash scripts/symbol_alias.sh $@ titanium_kmac_super_crypto_kem_dec OQS_KEM_titanium_kmac_super_decaps
	cd src/kem/titanium/upstream/kmac/Titanium_CCA_super && $(MAKE) clean

.objs/kem/titanium/kem_titanium_aes_super_upstream.a:
	cd src/kem/titanium/upstream/aes/Titanium_CCA_super && $(MAKE) clean && $(MAKE) $(MAKE_FLAGS_KEM_TITANIUM)
	$(RM) $@
	cp src/kem/titanium/upstream/aes/Titanium_CCA_super/libtitanium.a $@
	bash scripts/symbol_unexport.sh $@ src/kem/titanium/unexported_symbols_list.txt titanium_aes_super
	bash scripts/symbol_alias.sh $@ titanium_aes_super_crypto_kem_keypair OQS_KEM_titanium_aes_super_keypair
	bash scripts/symbol_alias.sh $@ titanium_aes_super_crypto_kem_enc OQS_KEM_titanium_aes_super_encaps
	bash scripts/symbol_alias.sh $@ titanium_aes_super_crypto_kem_dec OQS_KEM_titanium_aes_super_decaps
	cd src/kem/titanium/upstream/aes/Titanium_CCA_super && $(MAKE) clean
