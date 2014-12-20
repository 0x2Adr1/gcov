#ifndef BREAKPOINT_HH
# define BREAKPOINT_HH

# include <unordered_map>
# include <cstdint>
# include <list>
# include <capstone/capstone.h>
# include <sys/types.h>

# include "elf.hh"

enum
{
    IS_CALL = 1,
    IS_JMP = 2,
    IS_RET = 3
};

struct map_page
{
    std::uint64_t addr_begin_page;
    std::uint64_t len;
};

class Breakpoint
{
public:
    Breakpoint(pid_t pid_child, Elf* elf, csh* handle);
    ~Breakpoint();

    // put breakpoints on every RET/JMP/CALL in .text section
    void put_breakpoints();

    void restore_breakpoint(std::uint64_t vaddr);
    bool restore_opcode(std::uint64_t vaddr);

    void set_last_executable_addr(std::uint64_t vaddr);

    void parse_proc_pid_maps(pid_t pid_child);
    void mprotect_section_text(int prot);
    void mprotect_ext_lib(int prot);
    void mprotect_syscall(std::uint64_t vaddr_page, std::size_t len, int prot);

private:
    void put_0xcc(std::size_t i);
    int is_ret_call_jmp(char* mnemonic);

    std::uint64_t m_last_executable_addr;

    // I map an address with its original code before 0xCC was put
    std::unordered_map<std::uint64_t, std::uint64_t> m_opcode_backup;

    std::list<struct map_page> m_ext_lib_pages;
    struct map_page m_text_page;

    csh* m_handle;
    cs_insn* m_insn;
    pid_t m_pid_child;
    Elf* m_elf;
};

#endif /* !BREAKPOINT_HH */
