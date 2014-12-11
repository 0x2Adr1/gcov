#ifndef MY_SSCOV_HH
# define MY_SSCOV_HH

# include <string>
# include <fstream>
# include <elf.h>
# include <sys/user.h>

void my_sscov(char** argv);

class Elf
{
public:
    Elf(const std::string& elf_path);
    ~Elf();

    void sscov(unsigned long long rip, std::fstream& stream,
            struct user_regs_struct& user_regs);

    void find_text_section();

private:
    Elf64_Ehdr* m_ehdr;
    Elf64_Shdr* m_text_shdr;
    char* m_buf;
    int m_fd_elf_file;
    std::size_t m_elf_size;
};

#endif /* !MY_SSCOV_HH */
