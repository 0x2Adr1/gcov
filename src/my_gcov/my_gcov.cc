#include "../breakpoint.hh"
#include "../elf.hh"

#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <iostream>
#include <unordered_map>

#include <errno.h>
#include <inttypes.h>

static void trace_child(pid_t pid_child, char** argv)
{
    Elf elf(argv[2]);

    bool debug_info_available = elf.parse_dwarf();
    int status = 0;
    struct user_regs_struct user_regs;

    Breakpoint bp(pid_child, &elf);

    wait(&status);

    bp.put_breakpoints();

    bool is_call_to_ext_lib = false;
    bool flag = false;

    int i = 0;

    while (true)
    {
        ptrace(PTRACE_CONT, pid_child, 0, 0);

        wait(&status);

        if (WIFEXITED(status))
            break;

        if (!WIFSTOPPED(status))
        {
            std::cerr << "problem: we have not break" << std::endl;
            std::exit(1);
        }

        if (flag)
            bp.restore_breakpoint(user_regs.rip);
        /*if (is_call_to_ext_lib)
        {
            bp.restore_breakpoint(user_regs.rip);
            is_call_to_ext_lib = false;
        }*/

        ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);
        std::printf("BREAK ! rip = 0x%llx\n", user_regs.rip);

        user_regs.rip--;
        ptrace(PTRACE_SETREGS, pid_child, 0, &user_regs);

        bp.restore_opcode(user_regs.rip);

        /*if (!(is_call_to_ext_lib = bp.is_call_to_ext_lib(user_regs.rip)))
        {
            ptrace(PTRACE_SINGLESTEP, pid_child, 0, 0);
            bp.restore_breakpoint(user_regs.rip);
        }*/

        /*if (i == 4)
            std::exit(1);
        ++i;*/
        flag = true;
    }

    (void) is_call_to_ext_lib;
    (void) debug_info_available;
    (void) i;
}

void my_gcov(char** argv)
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
        std::cerr << "Error occured with execvp." << std::endl;
    }

    else
        trace_child(pid_child, argv);
}
