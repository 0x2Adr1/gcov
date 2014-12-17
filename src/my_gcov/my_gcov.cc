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

#include <errno.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <assert.h>

static void init_capstone(csh* handle)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, handle) != CS_ERR_OK)
    {
        std::cerr << "problem with capstone" << std::endl;
        std::exit(1);
    }
}

static void trace_child(pid_t pid_child, char** argv)
{
    Elf elf(argv[2]);

    int status = 0;
    struct user_regs_struct user_regs;
    csh handle;

    init_capstone(&handle);

    Breakpoint bp(pid_child, &elf, &handle);

    wait(&status);

    std::uint64_t main_addr = 0;
    bp.put_breakpoints(main_addr);

    bool flag = false;
    std::uint64_t begin_basic_block = main_addr;
    std::uint64_t end_basic_block = 0;

    while (true)
    {
        ptrace(PTRACE_CONT, pid_child, 0, 0);

        wait(&status);

        if (WIFEXITED(status))
            break;

        if (!WIFSTOPPED(status))
        {
            std::cerr << "problem: we have not break, it's weird" << std::endl;
            std::exit(1);
        }

        if (flag)
            bp.restore_breakpoint(user_regs.rip);

        ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);
        std::printf("BREAK ! rip = 0x%llx\n", user_regs.rip);

        // we need to go one byte before to execute the original instruction
        user_regs.rip--;

        if (begin_basic_block == 0)
            begin_basic_block = user_regs.rip;

        else
        {
            end_basic_block = user_regs.rip;
            assert(end_basic_block >= begin_basic_block);
        }

        ptrace(PTRACE_SETREGS, pid_child, 0, &user_regs);

        bp.restore_opcode(user_regs.rip);

        flag = true;

        if (end_basic_block != 0)
        {
            elf.gcov(begin_basic_block, end_basic_block, &handle);
            begin_basic_block = 0;
            end_basic_block = 0;
        }
    }

    if (elf.is_debug_info_available())
        elf.print_result_gcov();

    cs_close(&handle);
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
