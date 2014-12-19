#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <cstdlib>
#include <cstring>

#include <iostream>
#include <string>

#include <unistd.h>

#include "my_strace.hh"
#include "syscall_table.hh" // see syscall_table.py

static void trace_child(pid_t pid_child)
{
    int status = 0;
    struct user_regs_struct user_regs;
    bool enter_syscall = true;

    wait(&status);
    ptrace(PTRACE_SETOPTIONS, pid_child, 0, PTRACE_O_TRACESYSGOOD);

    const std::string syscall_name[] =
    {
        SYSCALL_TABLE()
    };

    while (true)
    {
        ptrace(PTRACE_SYSCALL, pid_child, 0, 0);
        wait(&status);

        if (WIFEXITED(status))
            break;

        // we stopped because of a syscall
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        {
            ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);

            if (enter_syscall)
            {
                std::cout << syscall_name[user_regs.orig_rax] << "() = ";
                enter_syscall = false;
            }

            else
            {
                std::cout << static_cast<long long>(user_regs.rax);
                std::cout << std::endl;
                enter_syscall = true;
            }
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
        execvp(argv[2], &argv[2]);
        std::cerr << "problem with execvp" << std::endl;
    }

    else
        trace_child(pid_child);
}
