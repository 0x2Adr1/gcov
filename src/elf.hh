#ifndef ELF_HH
# define ELF_HH

# include <sys/user.h>
# include <fstream>
# include <string>
# include <elf.h>
# include "dwarf.hh"

class Elf
{
public:
    Elf(const std::string& elf_path);
    ~Elf();

    void sscov(std::fstream& stream, const struct user_regs_struct& user_regs);

    Elf64_Shdr* find_section_by_name(const std::string&);

    void parse_dwarf();
    void addr2line(const struct user_regs_struct& user_regs);

private:
    Elf64_Ehdr* m_ehdr;
    Elf64_Shdr* m_text_shdr;
    unsigned char* m_buf;
    int m_fd_elf_file;
    std::size_t m_elf_size;

    Dwarf* m_dwarf;
};

#endif /* !ELF_HH */
