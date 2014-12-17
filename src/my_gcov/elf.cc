#include "../elf.hh"

#include <cstdlib>
#include <iostream>
#include <inttypes.h>

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

void Elf::gcov(std::uint64_t begin_basic_block, std::uint64_t end_basic_block,
        csh* handle)
{
    std::size_t count = 0;
    std::size_t offset = m_text_shdr->sh_offset;
    offset += begin_basic_block - m_text_shdr->sh_addr;

    cs_insn* insn;
    count = cs_disasm(*handle, &m_buf[offset],
            end_basic_block - begin_basic_block, begin_basic_block, 0, &insn);

    if (count > 0)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            if (!m_debug_info_available)
            {
                std::printf("0x%" PRIx64":\t%s\t\t%s\n", insn[i].address,
                        insn[i].mnemonic, insn[i].op_str);
            }

            else
            {
                m_dwarf->gcov(insn[i].address);
            }
        }

        cs_free(insn, count);
    }
}

void Elf::print_result_gcov()
{
    m_dwarf->print_result_gcov();
}

std::uint64_t Elf::get_entry_point()
{
    return m_ehdr->e_entry;
}
