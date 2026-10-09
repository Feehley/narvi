# narvi (C++) -- build, install, and clean.
#
# Targets:
#   make            build the narvi binary and the test programs (default)
#   make test       build and run all test suites
#   make install    install the narvi binary (PREFIX=/usr/local by default)
#   make uninstall  remove the installed binary
#   make clean      remove build artifacts (reset to downloaded state)
#
# Overridable: CXX, CXXFLAGS, CPPFLAGS, LDLIBS, PREFIX, BINDIR, DESTDIR.
# Needs zlib1g-dev liblzma-dev libzstd-dev liblz4-dev.

CXX      ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra
CPPFLAGS ?= -I.
LDLIBS   ?= -lz -llzma -lzstd -llz4
DEPFLAGS := -MMD -MP

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=
INSTALL ?= install

BUILD  := build
OBJDIR := $(BUILD)/obj

LIB_SRCS := $(filter-out narvi/cli.cpp,$(wildcard narvi/*.cpp))
LIB_OBJS := $(patsubst narvi/%.cpp,$(OBJDIR)/%.o,$(LIB_SRCS))
CLI_OBJ  := $(OBJDIR)/cli.o
BIN      := $(BUILD)/narvi

TESTS    := roundtrip nested verify fixups fdt fitrebuild cpio
TESTBINS := $(addprefix $(BUILD)/,$(TESTS))

.DEFAULT_GOAL := all
.PHONY: all test install uninstall clean help

all: $(BIN) $(TESTBINS)

$(BIN): $(LIB_OBJS) $(CLI_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

$(TESTBINS): $(BUILD)/%: $(OBJDIR)/t_%.o $(LIB_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

$(OBJDIR)/%.o: narvi/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(DEPFLAGS) -c $< -o $@

$(OBJDIR)/t_%.o: tests/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(DEPFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

test: $(TESTBINS)
	@for b in $(TESTBINS); do echo "== $${b##*/} =="; ./$$b || exit 1; done

install: $(BIN)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/narvi
	@echo "installed $(DESTDIR)$(BINDIR)/narvi"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/narvi
	@echo "removed $(DESTDIR)$(BINDIR)/narvi"

clean:
	rm -rf $(BUILD)
	rm -rf CMakeFiles CMakeCache.txt cmake_install.cmake CTestTestfile.cmake Testing
	@echo "narvi (C++): cleaned build artifacts"

help:
	@echo "narvi (C++) targets: all (default), test, install, uninstall, clean"

-include $(wildcard $(OBJDIR)/*.d)
