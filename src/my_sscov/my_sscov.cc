#include <fstream> // std::fstream
#include <iostream> // std::cerr

#include <cstdlib> // std::exit
#include <cstring> // std::memset

#include <sys/types.h> // pid_t
#include <sys/ptrace.h> // ptrace()
#include <sys/wait.h> // wait()
#include <sys/user.h> // struct user_regs_struct

#include <unistd.h> // fork()

#include "my_sscov.hh"

static void trace_child(pid_t pid_child, char** argv, std::fstream& file)
{
    Elf elf(argv[3]);

    int status = 0;
    struct user_regs_struct user_regs;

    wait(&status);

    while (true)
    {
        ptrace(PTRACE_SINGLESTEP, pid_child, 0, 0);

        wait(&status);

        if (WIFEXITED(status))
            break;

        ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);

        elf.sscov(user_regs.rip, file, user_regs);
    }
}

void my_sscov(char** argv)
{
    std::fstream file(argv[2], std::fstream::out);

    if (!file.is_open())
    {
        std::cerr << "Error opening file '" << argv[2] << "'" << std::endl;
        std::exit(1);
    }

    pid_t pid_child = fork();

    if (pid_child == -1)
    {
        std::cerr << "Error forking" << std::endl;
        std::exit(1);
    }

    else if (pid_child == 0)
    {
        ptrace(PTRACE_TRACEME);

        char* bin_argv[32];
        std::memset(bin_argv, 0, sizeof (char*) * 32);
        bin_argv[0] = argv[3];

        for (int i = 4, j = 1; i < 31 && argv[i]; ++i, ++j)
            bin_argv[j] = argv[i];

        execvp(argv[3], bin_argv);
    }

    else
        trace_child(pid_child, argv, file);

    file.close();
}
