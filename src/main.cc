#include <iostream>
#include <cstdlib>

#include "my_strace/my_strace.hh"
#include "my_sscov/my_sscov.hh"
#include "my_addr2line/my_addr2line.hh"
#include "my_gcov/my_gcov.hh"

static void usage(const char* custom_usage = nullptr)
{
    if (custom_usage)
        std::cout << custom_usage;

    else
        std::cout << "Usage: ./my_gcov --level{1|2|3|4} /path/to/binary [args]";

    std::cout << std::endl;
    std::exit(EXIT_FAILURE);
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
            usage("Usage: ./my_gcov --level2 <file> /path/to/binary [args]");

        my_sscov(argv);
    }

    else if (level_str == "--level3")
        my_addr2line(argv);

    else if (level_str == "--level4")
        my_gcov(argv);

    else
        usage();

    return EXIT_SUCCESS;
}
