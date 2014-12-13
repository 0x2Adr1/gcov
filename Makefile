CXX=g++
CXXFLAGS=-Wall -Wextra -Werror -pedantic -std=c++14 -gdwarf-4

OBJS=main.o my_strace/my_strace.o my_sscov/my_sscov.o my_sscov/elf.o \
     my_addr2line/elf.o my_addr2line/my_addr2line.o my_addr2line/dwarf.o
OBJS:=$(addprefix src/,$(OBJS))

all: $(OBJS)
	$(CXX) $^ -o my_gcov

clean:
	rm -rf $(OBJS)

distclean: clean
	rm -rf my_gcov
