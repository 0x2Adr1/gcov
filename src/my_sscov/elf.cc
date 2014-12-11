#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <unistd.h>

#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <iostream>

#include "my_sscov.hh"

Elf::Elf(const std::string& elf_path)
{
    struct stat buf;

    if ((m_fd_elf_file = open(elf_path.c_str(), O_RDONLY)) == -1)
    {
        std::cerr << "Error opening elf file" << std::endl;
        std::exit(1);
    }

    fstat(m_fd_elf_file, &buf);

    m_elf_size = buf.st_size;

    m_buf = static_cast<char*>(mmap(NULL, m_elf_size, PROT_READ, MAP_PRIVATE,
                m_fd_elf_file, 0));

    m_ehdr = reinterpret_cast<Elf64_Ehdr*>(m_buf);

    find_text_section();
}

Elf::~Elf()
{
    munmap(m_buf, m_elf_size);
    close(m_fd_elf_file);
}

void Elf::find_text_section()
{
    Elf64_Shdr* shdr_string =
        reinterpret_cast<Elf64_Shdr*>
        (&m_buf[m_ehdr->e_shoff + m_ehdr->e_shstrndx * m_ehdr->e_shentsize]);

    int index = m_ehdr->e_shoff;
    for (int i = 0; i < m_ehdr->e_shnum; ++i, index += m_ehdr->e_shentsize)
    {
        Elf64_Shdr* shdr = reinterpret_cast<Elf64_Shdr*>(&m_buf[index]);

        if (!std::strcmp(&m_buf[shdr_string->sh_offset + shdr->sh_name],
                    ".text"))
        {
            m_text_shdr = shdr;
            break;
        }
    }

    /*std::cout << std::hex << m_text_shdr->sh_offset << std::endl;
    std::cout << "0x" << m_text_shdr->sh_addr << std::endl;
    std::cout << m_text_shdr->sh_size << std::endl;*/
}

void Elf::sscov(unsigned long long rip, std::fstream& stream,
        struct user_regs_struct& user_regs)
{
    if (rip < m_text_shdr->sh_addr
            || rip > m_text_shdr->sh_addr + m_text_shdr->sh_size)
        return;

    stream << "0x" << std::hex << rip << ":";

    unsigned char* opcode = reinterpret_cast<unsigned char*>
        (&m_buf[m_text_shdr->sh_offset + (rip - m_text_shdr->sh_addr)]);

    if ((*opcode) == 0xE8)
        stream << " CALL";

    else if (*opcode == 0xC2 || *opcode == 0xC3)
        stream << " RET";

    else if ((*opcode >= 0xE9 && *opcode <= 0xEB)
            || (*opcode >= 0x70 && *opcode <= 0x7F)
            || (*opcode == 0x0F
                && *(opcode + 1) >= 0x80 && *(opcode + 1) <= 0x8F))
        stream << " JMP\t0x" << user_regs.eflags;

    stream << std::endl;
}
