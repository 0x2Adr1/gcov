#include "../dwarf.hh"

#include <cstdio>
#include <iostream>
#include <cstdlib>

#include <assert.h>

Dwarf::Dwarf(unsigned char* buf, Elf64_Shdr* debug_info,
        Elf64_Shdr* debug_str, Elf64_Shdr* debug_aranges,
        Elf64_Shdr* debug_line)
{
    m_debug_info = debug_info;
    m_debug_str = debug_str;
    m_debug_line = debug_line;
    m_debug_aranges = debug_aranges;

    assert(m_debug_info != nullptr);
    assert(m_debug_line != nullptr);
    assert(m_debug_aranges != nullptr);
    assert(m_debug_str != nullptr);

    m_buf = buf;
}

void Dwarf::map_range_addr_to_cu()
{
    struct debug_aranges_hdr* debug_aranges_hdr;

    std::size_t i = 0;

    while (i < m_debug_aranges->sh_size)
    {
        std::size_t i_tmp = i;
        debug_aranges_hdr = reinterpret_cast<struct debug_aranges_hdr*>
            (&m_buf[i + m_debug_aranges->sh_offset]);

        //std::cout << std::hex << debug_aranges_hdr->length << std::endl;

        i += sizeof (struct debug_aranges_hdr);

#if 0
        int* seg_selector = reinterpret_cast<int*>
            (&m_buf[i + m_debug_aranges->sh_offset]);
#endif

        i += 4;

        unsigned long long* addr_begin = reinterpret_cast<unsigned long long*>
            (&m_buf[i + m_debug_aranges->sh_offset]);

        i += debug_aranges_hdr->addr_size;

        //std::cout << std::hex << *addr_begin << std::endl;

        // TODO: not sure if offset is always 4 bytes ...
        unsigned int* offset = reinterpret_cast<unsigned int*>
            (&m_buf[i + m_debug_aranges->sh_offset]);

        //std::cout << std::hex << *offset << std::endl;

        i = i_tmp + debug_aranges_hdr->length;
        i += sizeof (debug_aranges_hdr->length);

        struct range_addr range_addr =
        {
            *addr_begin,
            *offset,
            debug_aranges_hdr->debug_info_offset,
            0, // will be set in get_debug_line_offset
            0, // will be set in get_debug_line_offset
            0  // will be set in get_debug_line_offset
        };

        get_debug_line_offset(range_addr);
        m_list_range.push_back(range_addr);
    }
}

void Dwarf::get_debug_line_offset(struct range_addr& range_addr)
{
    struct debug_info_hdr* debug_info_hdr;

    std::size_t offset = m_debug_info->sh_offset + range_addr.debug_info_offset;

    debug_info_hdr = reinterpret_cast<struct debug_info_hdr*>
        (&m_buf[offset]);

    offset += sizeof (struct debug_info_hdr) + 1;

    offset += 4; // we don't care about compiler name
    offset++; // we don't care about DW_AT_language

    //printf("debug info length = 0x%x\n", debug_info_hdr->length);

    range_addr.debug_str_file_name_offset =
        *reinterpret_cast<unsigned int*>(&m_buf[offset]);

    offset += 4;

    range_addr.debug_str_comp_dir_offset = *reinterpret_cast<unsigned int*>
        (&m_buf[offset]);

    offset += 4 + 2 * debug_info_hdr->addr_size;

    range_addr.debug_line_offset = *reinterpret_cast<unsigned int*>
        (&m_buf[offset]);
}

unsigned int Dwarf::get_line_number(unsigned long long rip,
        unsigned int debug_line_offset)
{
    struct debug_line_hdr* debug_line_hdr;
    std::size_t offset = m_debug_line->sh_offset + debug_line_offset;

    debug_line_hdr = reinterpret_cast<struct debug_line_hdr*> (&m_buf[offset]);

    m_reg_is_stmt = debug_line_hdr->default_is_stmt;

    offset = m_debug_line->sh_offset + debug_line_hdr->prologue_length + 11;

    offset = m_debug_line->sh_offset + debug_line_offset;
    for (; offset < m_debug_line->sh_size + m_debug_line->sh_offset; ++offset)
        std::printf("0x%x\n", m_buf[offset]);

    (void) rip;

    //std::exit(42);

    return 42;
}

void Dwarf::addr2line_print_instruction(unsigned long long rip,
        struct range_addr& range_addr)
{
    reset_registers();

    std::cout << std::hex << "0x" << rip << ": ";

    std::printf("%s/%s:%d\n",
            &m_buf[m_debug_str->sh_offset + range_addr.debug_str_comp_dir_offset],
            &m_buf[m_debug_str->sh_offset + range_addr.debug_str_file_name_offset],
            get_line_number(rip, range_addr.debug_line_offset));
}

void Dwarf::addr2line(const struct user_regs_struct& user_regs)
{
    unsigned long long rip = user_regs.rip;

    for (auto& elt : m_list_range)
        if (rip >= elt.begin && rip < (elt.begin + elt.offset))
        {
            addr2line_print_instruction(rip, elt);
            return;
        }
}

void Dwarf::reset_registers()
{
    m_reg_address = 0;
    m_reg_op_index = 0;
    m_reg_file = 1;
    m_reg_line = 1;
    m_reg_column = 0;
    m_reg_basic_block = 0;
    m_reg_end_sequence = 0;
    m_reg_prologue_end = 0;
    m_reg_epilogue_begin = 0;
    m_reg_isa = 0;
    m_reg_discriminator = 0;
}
