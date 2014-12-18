CXX = clang++
CXXFLAGS = -Wall -Wextra -Werror -pedantic -std=c++1y -O2
LDFLAGS = -lcapstone

OBJS = main.o my_strace/my_strace.o my_sscov/my_sscov.o my_sscov/elf.o \
       my_addr2line/elf.o my_addr2line/my_addr2line.o my_addr2line/dwarf.o \
       my_gcov/my_gcov.o my_gcov/elf.o my_gcov/dwarf.o breakpoint.o elf.o

OBJS := $(addprefix src/,$(OBJS))

all: $(OBJS)
	$(CXX) $^ $(LDFLAGS) -o my_gcov

clean:
	rm -rf $(OBJS)

distclean: clean
	rm -rf my_gcov
