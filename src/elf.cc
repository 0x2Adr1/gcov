#include "elf.hh"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

#include <iostream>
#include <cstring>

Elf::Elf(const std::string& elf_path) : m_dwarf(nullptr)
{
    struct stat buf;

    if ((m_fd_elf_file = open(elf_path.c_str(), O_RDONLY)) == -1)
    {
        std::cerr << "Error opening elf file" << std::endl;
        std::exit(1);
    }

    fstat(m_fd_elf_file, &buf);

    m_elf_size = buf.st_size;

    m_buf = static_cast<unsigned char*>(mmap(NULL, m_elf_size, PROT_READ,
                MAP_PRIVATE, m_fd_elf_file, 0));

    m_ehdr = reinterpret_cast<Elf64_Ehdr*>(m_buf);

    m_text_shdr = find_section_by_name(".text");
    m_dwarf = nullptr;
    m_debug_info_available = true;

    parse_dwarf();
}

Elf::~Elf()
{
    munmap(m_buf, m_elf_size);
    close(m_fd_elf_file);

    if (m_dwarf)
        delete m_dwarf;
}

Elf64_Shdr* Elf::find_section_by_name(const std::string& section_name)
{
    Elf64_Shdr* shdr_string =
        reinterpret_cast<Elf64_Shdr*>
        (&m_buf[m_ehdr->e_shoff + m_ehdr->e_shstrndx * m_ehdr->e_shentsize]);

    int index = m_ehdr->e_shoff;
    for (int i = 0; i < m_ehdr->e_shnum; ++i, index += m_ehdr->e_shentsize)
    {
        Elf64_Shdr* shdr = reinterpret_cast<Elf64_Shdr*>(&m_buf[index]);

        if (!std::strcmp((char*)(&m_buf[shdr_string->sh_offset + shdr->sh_name]),
                    section_name.c_str()))
            return shdr;
    }

    return nullptr;
}

bool Elf::is_debug_info_available() const
{
    return m_debug_info_available;
}
