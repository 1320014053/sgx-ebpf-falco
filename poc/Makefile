SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
CLANG ?= clang
CC := gcc
CXX := g++

ifneq ($(SGX_MODE),SIM)
$(error This POC only supports SGX_MODE=SIM)
endif
ifneq ($(filter $(SGX_DEBUG),0 1),$(SGX_DEBUG))
$(error SGX_DEBUG must be 0 or 1)
endif

BUILD := build/sim$(SGX_DEBUG)
SDK_BIN := $(SGX_SDK)/bin/x64
SDK_LIB := $(SGX_SDK)/lib64
OPT := $(if $(filter 1,$(SGX_DEBUG)),-O0 -g,-O2)
COMMON := -m64 $(OPT) -Wall -Wextra -Iinclude
HOST_FLAGS := $(COMMON) -I$(BUILD) -I$(SGX_SDK)/include -fPIC
TRUST_FLAGS := $(COMMON) -I$(BUILD) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
               -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong \
               -ffunction-sections -fdata-sections

.PHONY: all clean test
all: $(BUILD)/poc $(BUILD)/enclave.signed.so $(BUILD)/probe.bpf.o $(BUILD)/generator $(BUILD)/ring_tests

$(BUILD):
	mkdir -p $@

$(BUILD)/Enclave_u.c $(BUILD)/Enclave_u.h &: enclave/Enclave.edl include/event.h | $(BUILD)
	$(SDK_BIN)/sgx_edger8r --untrusted $< --search-path include --search-path $(SGX_SDK)/include --untrusted-dir $(BUILD)

$(BUILD)/Enclave_t.c $(BUILD)/Enclave_t.h &: enclave/Enclave.edl include/event.h | $(BUILD)
	$(SDK_BIN)/sgx_edger8r --trusted $< --search-path include --search-path $(SGX_SDK)/include --trusted-dir $(BUILD)

$(BUILD)/Enclave_u.o: $(BUILD)/Enclave_u.c $(BUILD)/Enclave_u.h
	$(CC) $(HOST_FLAGS) -c $< -o $@

$(BUILD)/main.o: host/main.cpp $(BUILD)/Enclave_u.h include/event.h include/event_logic.h
	$(CXX) $(HOST_FLAGS) -std=c++11 $(shell pkg-config --cflags libbpf) -c $< -o $@

$(BUILD)/poc: $(BUILD)/main.o $(BUILD)/Enclave_u.o
	$(CXX) $^ -o $@ -L$(SDK_LIB) -Wl,-rpath,$(SDK_LIB) -lsgx_urts_sim -lpthread $(shell pkg-config --libs libbpf) -lelf -lz

$(BUILD)/Enclave_t.o: $(BUILD)/Enclave_t.c $(BUILD)/Enclave_t.h
	$(CC) $(TRUST_FLAGS) -c $< -o $@

$(BUILD)/Enclave.o: enclave/Enclave.cpp $(BUILD)/Enclave_t.h include/event.h include/event_logic.h
	$(CXX) $(TRUST_FLAGS) -std=c++11 -nostdinc++ -fno-exceptions -fno-rtti -c $< -o $@

$(BUILD)/enclave.so: $(BUILD)/Enclave.o $(BUILD)/Enclave_t.o enclave/Enclave.lds
	$(CXX) $(filter %.o,$^) -o $@ -m64 -nostdlib -nodefaultlibs -nostartfiles -L$(SDK_LIB) \
	  -Wl,--no-undefined -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
	  -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
	  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	  -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections -Wl,--version-script=enclave/Enclave.lds \
	  -Wl,-z,relro,-z,now,-z,noexecstack

$(BUILD)/test-key.pem: | $(BUILD)
	openssl genrsa -3 -out $@ 3072

$(BUILD)/enclave.signed.so: $(BUILD)/enclave.so $(BUILD)/test-key.pem enclave/Enclave.config.xml
	$(SDK_BIN)/sgx_sign sign -key $(BUILD)/test-key.pem -enclave $< -out $@ -config enclave/Enclave.config.xml

$(BUILD)/probe.bpf.o: bpf/probe.bpf.c include/event.h | $(BUILD)
	$(CLANG) -g -O2 -target bpf -D__BPF__ -D__TARGET_ARCH_x86 -Iinclude -I/usr/include/$(shell $(CC) -dumpmachine) -c $< -o $@

$(BUILD)/generator: tests/generator.c include/event.h | $(BUILD)
	$(CC) $(COMMON) -std=c11 $< -o $@

$(BUILD)/ring_tests: tests/ring_tests.cpp $(BUILD)/Enclave_u.o $(BUILD)/Enclave_u.h include/event.h
	$(CXX) $(HOST_FLAGS) -std=c++11 $< $(BUILD)/Enclave_u.o -o $@ -L$(SDK_LIB) -Wl,-rpath,$(SDK_LIB) -lsgx_urts_sim

test: all
	LD_LIBRARY_PATH="$(SDK_LIB)$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}" $(BUILD)/ring_tests $(BUILD)/enclave.signed.so

clean:
	rm -rf build
