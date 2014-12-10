CXX=clang++
CXXFLAGS=-Wall -Wextra -Werror -pedantic -std=c++1y

OBJS=main.o my_strace/my_strace.o
OBJS:=$(addprefix src/,$(OBJS))

all: $(OBJS)

clean:
	rm -rf $(OBJS)

distclean: clean
	rm -rf my_gcov
