#include "../breakpoint.hh"
#include "../elf.hh"

#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <signal.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <iostream>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <assert.h>

#include <capstone/capstone.h>

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

    if (WIFEXITED(status))
        return;

    bp.parse_proc_pid_maps(pid_child);
    bp.put_breakpoints();

    std::uint64_t begin_basic_block = elf.get_entry_point();
    std::uint64_t end_basic_block = 0;
    std::uint64_t tmp_rip = 0;

    bp.set_last_writable_addr(elf.get_entry_point());

    bool child_is_in_ext_lib = false;
    bool flag = false;
    bool set_begin_basic_block = false;
    bool restore_breakpoint = false;

    while (true)
    {
        ptrace(PTRACE_CONT, pid_child, 0, 0);
        wait(&status);

        if (!flag)
        {
            bp.mprotect_ext_lib(PROT_READ | PROT_WRITE);
            flag = true;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        if (!WIFSTOPPED(status))
        {
            std::cerr << "problem: we have not break, it's weird" << std::endl;
            std::exit(1);
        }

        ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);
        /*std::printf("BREAK ! rip = 0x%llx\n", user_regs.rip);
        std::cout << "WSTOPSIG = " << WSTOPSIG(status) << std::endl;
        std::printf("instr = 0x%lx\n", ptrace(PTRACE_PEEKDATA, pid_child,
                    reinterpret_cast<void*>(user_regs.rip), 0));
        std::cout << std::endl;*/

        if (WSTOPSIG(status) == SIGSEGV)
        {
            //std::cout << "SEGV ! " << child_is_in_ext_lib << std::endl;
            if (!child_is_in_ext_lib)
            {
                bp.mprotect_ext_lib(PROT_READ | PROT_WRITE | PROT_EXEC);
                ptrace(PTRACE_SINGLESTEP, pid_child, 0, 0);
                wait(&status);
                ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);
                bp.set_last_writable_addr(user_regs.rip);
                bp.mprotect_section_text(PROT_READ | PROT_WRITE);
            }

            else
            {
                bp.mprotect_section_text(PROT_READ | PROT_WRITE | PROT_EXEC);

                ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);
                bp.set_last_writable_addr(user_regs.rip);

                if (elf.is_in_section_text(user_regs.rip))
                {
                    begin_basic_block = user_regs.rip;
                    set_begin_basic_block = false;
                }

                bp.mprotect_ext_lib(PROT_READ | PROT_WRITE);
            }

            child_is_in_ext_lib = !child_is_in_ext_lib;
            continue;
        }

        /*if (!bp.restore_opcode(user_regs.rip - 1))
            continue;*/

        if (restore_breakpoint)
        {
            bp.restore_breakpoint(tmp_rip);
            restore_breakpoint = false;
        }

        bp.restore_opcode(user_regs.rip - 1);
        restore_breakpoint = true;
        tmp_rip = user_regs.rip - 1;

        // we need to go one byte before to execute the original instruction
        user_regs.rip--;

        if (set_begin_basic_block)
            begin_basic_block = user_regs.rip;

        else
        {
            end_basic_block = user_regs.rip;
            elf.gcov(begin_basic_block, end_basic_block, &handle);
            /*std::cout << "begin\t=\t0x" << std::hex << begin_basic_block << std::endl;
            std::cout << "end\t=\t0x" << std::hex << end_basic_block << std::endl;
            std::cout << std::endl;*/
        }

        set_begin_basic_block = !set_begin_basic_block;

        ptrace(PTRACE_SETREGS, pid_child, 0, &user_regs);

        bp.set_last_writable_addr(user_regs.rip);

        if (set_begin_basic_block)
        {
            ptrace(PTRACE_SINGLESTEP, pid_child, 0, 0);
            wait(&status);
            ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);

            while (!elf.is_in_section_text(user_regs.rip)
                    && (WSTOPSIG(status) != SIGSEGV))
            {
                ptrace(PTRACE_SINGLESTEP, pid_child, 0, 0);
                wait(&status);
                ptrace(PTRACE_GETREGS, pid_child, 0, &user_regs);
            }

            if (WSTOPSIG(status) != SIGSEGV)
            {
                begin_basic_block = user_regs.rip;
                set_begin_basic_block = false;
            }
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
