#include <iostream>
#include <cstdlib>

#include "my_strace/my_strace.hh"
#include "my_sscov/my_sscov.hh"
#include "my_addr2line/my_addr2line.hh"
#include "my_gcov/my_gcov.hh"

static void usage()
{
    std::cout << "Usage: ./my_gcov --level{1|2|3|4} /path/to/binary [args]";
    std::cout << std::endl;

    std::exit(0);
}

int main(int argc, char *argv[])
{
    if (argc < 3)
        usage();

    std::string level_str = argv[1];

    if (level_str == "--level1")
        my_strace(argv);

    else if (level_str == "--level2")
    {
        if (argc < 4)
            usage();

        my_sscov(argv);
    }

    else if (level_str == "--level3")
        my_addr2line(argv);

    else if (level_str == "--level4")
        my_gcov(argv);

    else
        std::cout << "levels available are 1, 2, 3 and 4" << std::endl;
}
