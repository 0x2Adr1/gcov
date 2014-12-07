#include <sys/types.h> // pid_t
#include <sys/ptrace.h> // ptrace()
#include <sys/wait.h> // waitpid()
#include <sys/user.h> // struct user_regs_struct
#include <cstdlib> // std::exit()
#include <iostream> // std::cerr

#include <unistd.h> // fork()

#include "my_strace.hh"
#include "syscall_table.hh" // see syscall_table.py

static void trace_child(pid_t pid_child)
{
    int status = 0;
    struct user_regs_struct user_regs;
    bool enter_syscall = true;

    // our child tell us that he is starting execution
    wait(&status);

    const std::string syscall_name[] =
    {
        SYSCALL_NAME()
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

void my_strace(const std::string& bin_path, char *argv[])
{
    pid_t pid_child = fork();

    if (pid_child == -1)
    {
        std::cerr << "FORK ERROR" << std::endl;
        std::exit(1);
    }

    else if (pid_child == 0)
    {
        ptrace(PTRACE_TRACEME);
        pid_child = getpid();

        char* const bin_argv[] =
        {
            const_cast<char*>(bin_path.c_str()),
            NULL
        };

        execvp(bin_path.c_str(), bin_argv);
    }

    else
        trace_child(pid_child);
}
