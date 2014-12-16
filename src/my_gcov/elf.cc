#include "../elf.hh"

#include <cstdlib>

void Elf::get_section_text(struct section_text& section_text) const
{
    section_text.buf = &m_buf[m_text_shdr->sh_offset];
    section_text.size = m_text_shdr->sh_size;
    section_text.vaddr = m_text_shdr->sh_addr;
}

bool Elf::is_in_section_text(std::uint64_t vaddr) const
{
    return vaddr >= m_text_shdr->sh_addr
        && vaddr < (m_text_shdr->sh_addr + m_text_shdr->sh_size);
}
