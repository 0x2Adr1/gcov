#include "breakpoint.hh"

#include <iostream>
#include <inttypes.h>
#include <sys/ptrace.h>
#include <cstdlib>

Breakpoint::Breakpoint(pid_t pid_child, Elf* elf)
{
    m_elf = elf;
    m_pid_child = pid_child;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_handle) != CS_ERR_OK)
    {
        std::cerr << "problem with capstone" << std::endl;
        std::exit(1);
    }
}

Breakpoint::~Breakpoint()
{
    cs_close(&m_handle);
}

void Breakpoint::put_breakpoints()
{
    std::size_t count;

    struct section_text section_text;
    m_elf->get_section_text(section_text);

    count = cs_disasm(m_handle, section_text.buf, section_text.size,
            section_text.vaddr, 0, &m_insn);

    if (count > 0)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            std::printf("0x%" PRIx64":\t%s\t\t%s\n", m_insn[i].address,
              m_insn[i].mnemonic, m_insn[i].op_str);

            int code = 0;
            if ((code = is_ret_call_jmp(m_insn[i].mnemonic)))
            {
                if (code == IS_CALL)
                {
                    std::uint64_t addr = std::strtol(m_insn[i].op_str, NULL, 16);
                    if (addr != 0 && !m_elf->is_in_section_text(addr))
                    {
                        //std::printf("on va jump dans une lib externe :(\n");
                        put_0xcc(i, true);
                        put_0xcc(++i);
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

    //std::printf("breakpoint put at 0x%lx : %d\n", m_insn[i].address, call_ext_lib);

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

void Breakpoint::restore_opcode(std::uint64_t vaddr)
{
    ptrace(PTRACE_POKEDATA, m_pid_child,
            reinterpret_cast<void*>(vaddr),
            reinterpret_cast<void*>(m_opcode_backup[vaddr].first));

    /*std::printf("word 0x%lx restore at 0x%lx\n", m_opcode_backup[vaddr].first,
            vaddr);*/
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

bool Breakpoint::is_call_to_ext_lib(std::uint64_t vaddr)
{
    return m_opcode_backup[vaddr].second;
}
