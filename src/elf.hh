#ifndef ELF_HH
# define ELF_HH

# include <sys/user.h>
# include <fstream>
# include <string>
# include <elf.h>
# include "dwarf.hh"
# include <capstone/capstone.h>

struct section_text
{
    unsigned char* buf;
    std::size_t size;
    unsigned long long vaddr;
};

class Elf
{
public:
    Elf(const std::string& elf_path);
    ~Elf();


    Elf64_Shdr* find_section_by_name(const std::string&);

    void parse_dwarf();

    void addr2line(const struct user_regs_struct& user_regs);
    void sscov(std::fstream& stream, const struct user_regs_struct& user_regs);
    void gcov(std::uint64_t begin_basic_block, std::uint64_t end_basic_block,
            csh* handle);

    void get_section_text(struct section_text& section_text) const;

    bool is_in_section_text(std::uint64_t vaddr) const;
    bool is_debug_info_available() const;

    void write_result_gcov(char* bin_name);

    std::uint64_t get_entry_point();

private:
    Elf64_Ehdr* m_ehdr;
    Elf64_Shdr* m_text_shdr;
    unsigned char* m_buf;
    int m_fd_elf_file;
    std::size_t m_elf_size;
    bool m_debug_info_available;

    Dwarf* m_dwarf;
};

#endif /* !ELF_HH */
