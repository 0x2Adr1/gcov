#include "../elf.hh"

#include <iostream>
#include <cstdio>

void Elf::addr2line(const struct user_regs_struct& user_regs)
{
#if 0
    Elf64_Shdr* aranges_shdr = find_section_by_name(".debug_aranges");

    std::cout << "sh_addr .debug_aranges " << aranges_shdr->sh_addr << std::endl;
    std::cout << "sh_name .debug_aranges " << aranges_shdr->sh_name << std::endl;
    std::cout << "sh_offset .debug_aranges " << aranges_shdr->sh_offset << std::endl;
    std::cout << "sh_size .debug_aranges " << aranges_shdr->sh_size << std::endl;

    for (std::size_t i = 0; i < aranges_shdr->sh_size; ++i)
        std::printf("%x\n", m_buf[aranges_shdr->sh_offset + i]);

    (void) user_regs;
#endif

    unsigned long long rip = user_regs.rip;

    if (rip < m_text_shdr->sh_addr
            || rip > m_text_shdr->sh_addr + m_text_shdr->sh_size)
        return;

    m_dwarf->addr2line(user_regs);
}

void Elf::parse_dwarf()
{
    m_dwarf = new Dwarf(m_buf, find_section_by_name(".debug_info"),
            find_section_by_name(".debug_str"),
            find_section_by_name(".debug_aranges"),
            find_section_by_name(".debug_line"));

    m_dwarf->map_range_addr_to_cu();
}
