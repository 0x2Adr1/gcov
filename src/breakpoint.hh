#ifndef BREAKPOINT_HH
# define BREAKPOINT_HH

# include <unordered_map>
# include <cstdint>
# include <utility>
# include <capstone/capstone.h>
# include <sys/types.h>

# include "elf.hh"

enum
{
    IS_CALL = 1,
    IS_JMP = 2,
    IS_RET = 3
};

class Breakpoint
{
public:
    Breakpoint(pid_t, Elf*, csh* handle);
    ~Breakpoint();

    void put_breakpoints();
    void restore_breakpoint(std::uint64_t vaddr);
    void restore_opcode(std::uint64_t vaddr);
    bool is_call_to_ext_lib(std::uint64_t vaddr);

    void mprotect_section_text(int prot);

private:
    void put_0xcc(std::size_t i, bool call_ext_lib = false);
    int is_ret_call_jmp(char* mnemonic);

    // we map an address to a pair
    // the pair is composed by a word of data and a bool who tells
    // if it is a call to an external library
    std::unordered_map<std::uint64_t, std::pair<std::uint64_t, bool> >
        m_opcode_backup;

    csh* m_handle;
    cs_insn* m_insn;
    pid_t m_pid_child;
    Elf* m_elf;
};

#endif /* !BREAKPOINT_HH */
