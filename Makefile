CC = clang

# Directories.
BUILD_DIR := build
SRC_DIR := src
MODULES_DIR := modules

COMMON_DIR := $(MODULES_DIR)/common
DPDK_COMMON_DIR := $(MODULES_DIR)/dpdk-common

# Common source and build directories.
COMMON_BUILD_DIR := $(COMMON_DIR)/build
COMMON_SRC_DIR := $(COMMON_DIR)/src

# The DPDK Common source and objects directories.
DPDK_COMMON_SRC_DIR := $(DPDK_COMMON_DIR)/src
DPDK_COMMON_OBJS_DIR := $(DPDK_COMMON_DIR)/objs

# Common objects.
COMMON_OBJS := $(COMMON_BUILD_DIR)/utils.o $(COMMON_BUILD_DIR)/cmd_line.o $(COMMON_BUILD_DIR)/config.o

# The DPDK Common objects.
DPDK_COMMON_OBJS := $(DPDK_COMMON_OBJS_DIR)/dpdk_common.o

# Source and out files.
SEQ_SRC := sequence.c
SEQ_OUT := sequence.o

CMD_LINE_SRC := cmd_line.c
CMD_LINE_OUT := cmd_line.o

# Main object files.
MAIN_OBJS := $(BUILD_DIR)/$(SEQ_OUT) $(BUILD_DIR)/$(CMD_LINE_OUT)

MAIN_SRC := main.c
MAIN_OUT := pcktbatch

# Global and main flags.
OBJ_FLAGS := -g -O2
MAIN_FLAGS := -g -pthread -lyaml

PKGCONF ?= pkg-config

# For compiling DPDK applications
# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS += -DALLOW_EXPERIMENTAL_API
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

ifeq ($(MAKECMDGOALS),static)
# Check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif

# Chains.
all: mk_build common dpdk_common sequence cmd_line main
nocommon: mk_build dpdk_common sequence cmd_line main

# Creates the build directory if it doesn't already exist.
mk_build:
	mkdir -p $(BUILD_DIR)

# Build The DPDK Common objects.
dpdk_common:
	$(MAKE) -C $(DPDK_COMMON_DIR)

# Build and install the Packet Batch common submodule (this includes libyaml).
common:
	$(MAKE) -C $(COMMON_DIR)/
	$(MAKE) -C $(COMMON_DIR)/ install

# The sequence file.
sequence: mk_build
	$(CC) -I $(COMMON_SRC_DIR) -I $(DPDK_COMMON_SRC_DIR) $(OBJ_FLAGS) -c -o $(BUILD_DIR)/$(SEQ_OUT) $(SRC_DIR)/$(SEQ_SRC)

# The command line file.
cmd_line: mk_build
	$(CC) -I $(DPDK_COMMON_SRC_DIR) $(OBJ_FLAGS) -c -o $(BUILD_DIR)/$(CMD_LINE_OUT) $(SRC_DIR)/$(CMD_LINE_SRC)

# The main program.
main: mk_build $(COMMON_OBJS)
	$(CC) -I $(COMMON_SRC_DIR) -I $(DPDK_COMMON_SRC_DIR) $(CFLAGS) $(MAIN_FLAGS) -o $(BUILD_DIR)/$(MAIN_OUT) $(COMMON_OBJS) $(DPDK_COMMON_OBJS) $(LDFLAGS_STATIC) $(MAIN_OBJS) $(SRC_DIR)/$(MAIN_SRC)

# Cleanup (remove build files).
clean:
	$(MAKE) -C $(COMMON_DIR)/ clean
	$(MAKE) -C $(DPDK_COMMON_DIR)/ clean
	rm -f $(BUILD_DIR)/*.o
	rm -f $(BUILD_DIR)/$(MAIN_OUT)

# Install executable to $PATH.
install:
	cp $(BUILD_DIR)/$(MAIN_OUT) /usr/bin/$(MAIN_OUT)

.PHONY:

.DEFAULT: all