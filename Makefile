LIBECC_ERROR  = Error: you asked for compilation while no libecc is present!
LIBECC_ERROR += Please install libecc using "make install_libecc" and run
LIBECC_ERROR += your "make" command again.

OPENPGP_LDFLAGS =
ifeq ($(USE_SANITIZERS),1)
  OPENPGP_LDFLAGS += -fsanitize=undefined -fsanitize=address -fsanitize=leak
endif

OPENPGP_CFLAGS = -DUSE_CRYPTOFUZZ -DWITH_OPENPGP_LAYER -DWITH_STDLIB -Wall -Wextra

OPENPGP_CFLAGS += $(EXTRA_OPENPGP_CFLAGS)

EXTERNAL_DEPS=libecc/src/external_deps/rand.c libecc/src/external_deps/print.c

.ONESHELL:

all:
	@if [ ! -d libecc/ ]; then \
		echo $(LIBECC_ERROR); \
		exit; \
	fi;
	@echo "[+] Compiling libecc"
	@cd libecc && VERBOSE=1 CRYPTOFUZZ=1 USE_SANITIZERS=$(USE_SANITIZERS) EXTRA_CFLAGS=$(EXTRA_OPENPGP_CFLAGS) $(MAKE) && cd -
	@echo "[+] Compiling openpgp-libecc"
	@mkdir -p build
	$(CC) $(OPENPGP_CFLAGS) $(EXTERNAL_DEPS) src/openpgp_layer.c src/test/openpgp_layer_test.c src/test_main.c -I./libecc/src/ libecc/build/libsign.a $(OPENPGP_LDFLAGS) -o build/openpgp_test

clean:
	@echo "[+] Cleaning libecc"
	@cd libecc && $(MAKE) clean && cd -
	@echo "[+] Cleaning openpgp-libecc"
	@rm -rf build

LIBECC_REPO=https://github.com/libecc/libecc.git
install_libecc:
	@if [ ! -d libecc/ ]; then \
		echo "[+] Cloning the libecc repository"; \
		git clone $(LIBECC_REPO); \
	else \
		echo "[+] libecc repository already cloned!"; \
	fi;

remove_libecc:
	@echo "[+] Cleaning the libecc repo"
	@rm -rf libecc



