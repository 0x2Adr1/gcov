#include <sys/types.h> // pid_t
#include <sys/ptrace.h> // ptrace()
#include <sys/wait.h> // waitpid()
#include <sys/user.h> // struct user_regs_struct

#include <cstdlib> // std::exit()
#include <cstring> // memset

#include <iostream> // std::cerr
#include <string>

#include <unistd.h> // fork()

#include "my_strace.hh"
#include "syscall_table.hh" // see syscall_table.py

static void trace_child(pid_t pid_child)
{
    int status = 0;
    struct user_regs_struct user_regs;
    bool enter_syscall = true;

    // our child tell us that he is starting execution (execve)
    wait(&status);

    const std::string syscall_name[] =
    {
        SYSCALL_TABLE()
    };

    while (true)
    {
        ptrace(PTRACE_SYSCALL, pid_child, 0, 0);
        // this time he tell us that he enters in a syscall
        wait(&status);

        if (WIFEXITED(status))
            break;

        ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);

        if (enter_syscall)
        {
            std::cout << syscall_name[user_regs.orig_rax] << "() = ";
            enter_syscall = false;
        }

        else
        {
            std::cout << static_cast<signed long long>(user_regs.rax);
            std::cout << std::endl;
            enter_syscall = true;
        }
    }
}

void my_strace(char** argv)
{
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
        bin_argv[0] = argv[2];

        for (int i = 3, j = 1; i < 31 && argv[i]; ++i, ++j)
            bin_argv[j] = argv[i];

        execvp(argv[2], bin_argv);
    }

    else
        trace_child(pid_child);
}
