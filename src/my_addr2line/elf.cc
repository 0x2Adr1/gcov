#include "../elf.hh"

#include <iostream>
#include <cstdio>

void Elf::addr2line(const struct user_regs_struct& user_regs)
{
    std::uint64_t rip = user_regs.rip;

    if (rip < m_text_shdr->sh_addr
            || rip > (m_text_shdr->sh_addr + m_text_shdr->sh_size))
        return;

    m_dwarf->addr2line(user_regs);
}

void Elf::parse_dwarf()
{
    if (m_dwarf || !m_debug_info_available)
        return;

    Elf64_Shdr* debug_info = find_section_by_name(".debug_info");
    Elf64_Shdr* debug_str = find_section_by_name(".debug_str");
    Elf64_Shdr* debug_aranges = find_section_by_name(".debug_aranges");
    Elf64_Shdr* debug_line = find_section_by_name(".debug_line");
    Elf64_Shdr* debug_abbrev = find_section_by_name(".debug_abbrev");

    if (!debug_info || !debug_str || !debug_aranges || !debug_line
            || !debug_abbrev)
    {
        m_debug_info_available = false;
        return;
    }

    m_dwarf = new Dwarf(m_buf, debug_info, debug_str, debug_aranges,
            debug_line, debug_abbrev);

    m_dwarf->map_range_addr_to_cu();
}
