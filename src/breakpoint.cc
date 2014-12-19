#include "breakpoint.hh"

#include <iostream>
#include <inttypes.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <sstream>

Breakpoint::Breakpoint(pid_t pid_child, Elf* elf, csh* handle)
{
    m_elf = elf;
    m_pid_child = pid_child;
    m_handle = handle;
}

Breakpoint::~Breakpoint()
{
}

void Breakpoint::set_last_writable_addr(std::uint64_t vaddr)
{
    m_last_writable_addr = vaddr;
}

void Breakpoint::parse_proc_pid_maps(pid_t pid_child)
{
    std::ostringstream file_path;
    file_path << "/proc/" << pid_child << "/maps";

    std::ifstream file_stream(file_path.str());

    std::string line;

    while (std::getline(file_stream, line))
    {
        std::istringstream istring(line.c_str());
        std::string range_string;
        std::string permissions;
        bool exec_perm = false;

        istring >> range_string;
        istring >> permissions;

        std::istringstream range_istring(range_string);
        std::string begin_addr_string;
        std::string end_addr_string;

        std::getline(range_istring, begin_addr_string, '-');
        std::getline(range_istring, end_addr_string);

        for (std::size_t i = 0; i < permissions.length(); ++i)
            if (permissions[i] == 'x')
                exec_perm = true;

        if (exec_perm)
        {
            std::uint64_t begin_addr = std::strtoll(begin_addr_string.c_str(),
                    NULL, 16);
            std::uint64_t end_addr = std::strtoll(end_addr_string.c_str(),
                    NULL, 16);

            struct map_page map_page =
            {
                begin_addr,
                end_addr - begin_addr
            };

            std::size_t i = 0;
            while (begin_addr_string[i] == '0')
                i++;

            if (begin_addr_string[i] == '4')
                m_text_page = map_page;

            else
                m_ext_lib_pages.push_back(map_page);
        }
    }
}

void Breakpoint::mprotect_section_text(int prot)
{
    struct section_text section_text;
    m_elf->get_section_text(section_text);

    mprotect_syscall(section_text.vaddr & (~4095), section_text.size, prot);
}

void Breakpoint::mprotect_ext_lib(int prot)
{
    for (auto& elt : m_ext_lib_pages)
        mprotect_syscall(elt.addr_begin_page, elt.len, prot);
}

void Breakpoint::mprotect_syscall(std::uint64_t vaddr_page, std::size_t len,
        int prot)
{
    // syscall and 0xCC
    std::uint64_t code = 0xCC050F;
    struct user_regs_struct user_regs;
    struct user_regs_struct orig_regs;
    int status;

    ptrace(PTRACE_GETREGS, m_pid_child, 0, &user_regs);
    ptrace(PTRACE_GETREGS, m_pid_child, 0, &orig_regs);

    /*std::cout << std::endl;
    std::cout << "rip = 0x" << std::hex << user_regs.rip << std::endl;
    std::cout << "prot = " << prot << std::endl;
    std::cout << "last writable addr = 0x" << std::hex << m_last_writable_addr << std::endl;
    std::cout << "mprotect addr = 0x" << std::hex << vaddr_page << std::endl;*/

    std::uint64_t orig_code = ptrace(PTRACE_PEEKDATA, m_pid_child,
            reinterpret_cast<void*>(m_last_writable_addr), 0);

    user_regs.rip = m_last_writable_addr;
    user_regs.rax = 10;
    user_regs.rdi = vaddr_page;
    user_regs.rsi = len;
    user_regs.rdx = prot;

    ptrace(PTRACE_POKEDATA, m_pid_child,
            reinterpret_cast<void*>(m_last_writable_addr),
            reinterpret_cast<void*>(code));

    ptrace(PTRACE_SETREGS, m_pid_child, 0, &user_regs);
    ptrace(PTRACE_CONT, m_pid_child, 0, 0);
    wait(&status);

    /*std::cout << "WSTOPSIG = " << WSTOPSIG(status) << std::endl;
    if (WSTOPSIG(status) == SIGSEGV)
        std::exit(1);*/

    ptrace(PTRACE_SETREGS, m_pid_child, 0, &orig_regs);
    ptrace(PTRACE_POKEDATA, m_pid_child,
            reinterpret_cast<void*>(m_last_writable_addr),
            reinterpret_cast<void*>(orig_code));

    //std::cout << std::endl;
}

void Breakpoint::put_breakpoints()
{
    std::size_t count;

    struct section_text section_text;
    m_elf->get_section_text(section_text);

    count = cs_disasm(*m_handle, section_text.buf, section_text.size,
            section_text.vaddr, 0, &m_insn);

    if (count > 0)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            /*std::printf("0x%" PRIx64":\t%s\t\t%s\n", m_insn[i].address,
              m_insn[i].mnemonic, m_insn[i].op_str);*/

            int code = 0;
            if ((code = is_ret_call_jmp(m_insn[i].mnemonic)))
            {
                if (code == IS_CALL)
                {
                    std::uint64_t addr = std::strtoll(m_insn[i].op_str, NULL, 16);
                    if (addr != 0 && !m_elf->is_in_section_text(addr))
                    {
                        put_0xcc(i, true);
                        put_0xcc(++i, true);
                        continue;
                    }
                }

                put_0xcc(i);
            }
        }

        cs_free(m_insn, count);
    }
}

void Breakpoint::put_0xcc(std::size_t i, bool call_ext_lib)
{
    std::uint64_t word;
    word = ptrace(PTRACE_PEEKDATA, m_pid_child,
            reinterpret_cast<void*>(m_insn[i].address), 0);

    //std::printf("old data = 0x%lx\n", word);

    std::uint64_t data = (word & 0xFFFFFFFFFFFFFF00) | 0xCC;

    m_opcode_backup.insert({m_insn[i].address,
            std::make_pair<std::uint64_t, bool>(std::move(word),
                    std::move(call_ext_lib))});

    ptrace(PTRACE_POKEDATA, m_pid_child,
            reinterpret_cast<void*>(m_insn[i].address),
            reinterpret_cast<void*>(data));

    std::printf("breakpoint put at 0x%lx : %d\n", m_insn[i].address, call_ext_lib);

    word = ptrace(PTRACE_PEEKDATA, m_pid_child,
            reinterpret_cast<void*>(m_insn[i].address), 0);

    //std::printf("new data = 0x%lx\n", word);
}

int Breakpoint::is_ret_call_jmp(char* mnemonic)
{
    std::string s(mnemonic);

    if (s == "call" || s == "callq")
        return IS_CALL;

    else if (s[0] == 'j')
        return IS_JMP;

    else if (s == "ret" || s == "retq")
        return IS_RET;

    return 0;
}

bool Breakpoint::restore_opcode(std::uint64_t vaddr)
{
    if (m_opcode_backup.find(vaddr) == m_opcode_backup.end())
        return false;

    std::uint64_t data = ptrace(PTRACE_PEEKDATA, m_pid_child,
            reinterpret_cast<void*>(vaddr));

    data &= 0xFFFFFFFFFFFFFF00;
    data |= (m_opcode_backup[vaddr].first & 0x00000000000000FF);

    ptrace(PTRACE_POKEDATA, m_pid_child,
            reinterpret_cast<void*>(vaddr),
            reinterpret_cast<void*>(data));

    /*std::printf("word 0x%lx restore at 0x%lx\n", m_opcode_backup[vaddr].first,
            vaddr);*/

    return true;
}

void Breakpoint::restore_breakpoint(std::uint64_t vaddr)
{
    std::uint64_t word = ptrace(PTRACE_PEEKDATA, m_pid_child,
            reinterpret_cast<void*>(vaddr), 0);

    std::uint64_t data = (word & 0xFFFFFFFFFFFFFF00) | 0xCC;

    ptrace(PTRACE_POKEDATA, m_pid_child,
            reinterpret_cast<void*>(vaddr),
            reinterpret_cast<void*>(data));

    //std::cout << "breakpoint restore at 0x" << std::hex << vaddr << std::endl;
}

bool Breakpoint::is_call_to_ext_code(std::uint64_t vaddr)
{
    return m_opcode_backup[vaddr].second;
}
