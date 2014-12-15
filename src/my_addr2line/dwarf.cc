#include "../dwarf.hh"

#include <utility>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>

#include <assert.h>

#include <dwarf.h>

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

Dwarf::~Dwarf()
{
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

        i += sizeof (struct debug_aranges_hdr);

#if 0
        int* seg_selector = reinterpret_cast<int*>
            (&m_buf[i + m_debug_aranges->sh_offset]);
#endif

        i += 4;

        unsigned long long* addr_begin = reinterpret_cast<unsigned long long*>
            (&m_buf[i + m_debug_aranges->sh_offset]);

        i += debug_aranges_hdr->addr_size;

        // TODO: not sure if offset is always 4 bytes ...
        unsigned int* offset = reinterpret_cast<unsigned int*>
            (&m_buf[i + m_debug_aranges->sh_offset]);

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

    range_addr.debug_str_file_name_offset =
        *reinterpret_cast<unsigned int*>(&m_buf[offset]);

    offset += 4;

    range_addr.debug_str_comp_dir_offset = *reinterpret_cast<unsigned int*>
        (&m_buf[offset]);

    offset += 4 + 2 * debug_info_hdr->addr_size;

    range_addr.debug_line_offset = *reinterpret_cast<unsigned int*>
        (&m_buf[offset]);

    unsigned char* comp_dir =
        &m_buf[m_debug_str->sh_offset + range_addr.debug_str_comp_dir_offset];
    unsigned char* file_name =
        &m_buf[m_debug_str->sh_offset + range_addr.debug_str_file_name_offset];
    std::string file_path(reinterpret_cast<char*>(comp_dir));
    std::string file_name_string(reinterpret_cast<char*>(file_name));

    file_path += "/" + file_name_string;

    m_map_ifstream.insert({file_path,
            std::make_shared<std::ifstream>(file_path)});
}

void Dwarf::handle_extended_opcode(std::size_t& offset)
{
    ++offset;
    std::size_t length = m_buf[offset++];

    if (length == 0)
    {
        std::cerr << "Length for extended opcode is null." << std::endl;
        std::exit(1);
    }

    unsigned char extended_opcode = m_buf[offset];

    switch (extended_opcode)
    {
        case DW_LNE_end_sequence:
            reset_registers();
            m_reg_end_sequence = 1;
            break;

        case DW_LNE_set_address:
            m_reg_address = *reinterpret_cast<unsigned long long*>
                (&m_buf[offset + 1]);
            m_reg_op_index = 0;
            break;

        case DW_LNE_define_file:
            break;

        case DW_LNE_set_discriminator:
            break;

        case DW_LNE_lo_user:
            break;

        case DW_LNE_hi_user:
            break;

        default:
            std::printf("Uknown extended opcode 0x%x\n", extended_opcode);
            std::exit(1);
            break;
    }

    offset += length;
}

bool Dwarf::handle_special_opcode(std::size_t& offset,
        struct debug_line_hdr* debug_line_hdr, unsigned long long rip)
{
    unsigned char adjusted_opcode = m_buf[offset] - debug_line_hdr->opcode_base;
    int op_advance = adjusted_opcode / debug_line_hdr->line_range;

    unsigned long long tmp_address = m_reg_address;

    m_reg_address += op_advance;

    if (rip > tmp_address && rip < m_reg_address)
        return true;

    op_advance = adjusted_opcode % debug_line_hdr->line_range;
    op_advance += debug_line_hdr->line_base;
    m_reg_line += op_advance;

    ++offset;

    // we have the line corresponding to the address
    if (rip == m_reg_address)
        return true;

    return false;
}

bool Dwarf::handle_standard_opcode(std::size_t& offset,
        struct debug_line_hdr* debug_line_hdr, unsigned long long rip)
{
    unsigned char opcode = m_buf[offset];
    int op_advance = 0;
    unsigned long long tmp_address = 0;

    switch (opcode)
    {
        case DW_LNS_copy:
            std::printf("DW_LNS_copy not implemented yet :(\n");
            break;

        case DW_LNS_advance_pc:
            op_advance = debug_line_hdr->min_inst_length * m_buf[++offset];
            tmp_address = m_reg_address;
            m_reg_address += op_advance;
            if (rip > tmp_address && rip < m_reg_address)
                return true;
#if PRINT_DEBUG
            std::printf("DW_LNS_advance_pc, address is now 0x%llx\n",
                    m_reg_address);
#endif
            break;

        case DW_LNS_advance_line:
            std::printf("DW_LNS_advance_line not implemented yet :(\n");
            break;

        case DW_LNS_set_file:
            std::printf("DW_LNS_set_file not implemented yet :(\n");
            break;

        case DW_LNS_set_column:
            std::printf("DW_LNS_set_column not implemented yet :(\n");
            break;

        case DW_LNS_negate_stmt:
            std::printf("DW_LNS_set_negate_stmt not implemented yet :(\n");
            break;

        case DW_LNS_set_basic_block:
            std::printf("DW_LNS_set_basic_block not implemented yet :(\n");
            break;

        case DW_LNS_const_add_pc:
            tmp_address = m_reg_address;
            // it's like we call handle_special_opcode with the opcode 0xFF
            m_reg_address += ((255 - debug_line_hdr->opcode_base)
                    / debug_line_hdr->line_range)
                    * debug_line_hdr->min_inst_length;

            if (rip > tmp_address && rip < m_reg_address)
                return true;

            break;

        case DW_LNS_fixed_advance_pc:
            std::printf("DW_LNS_fixed_advance_pc not implemented yet :(\n");
            break;

        case DW_LNS_set_prologue_end:
            std::printf("DW_LNS_set_prologue_end not implemented yet :(\n");
            break;

        case DW_LNS_set_epilogue_begin:
            std::printf("DW_LNS_set_epilogue_begin not implemented yet :(\n");
            break;

        case DW_LNS_set_isa:
            std::printf("DW_LNS_set_isa not implemented yet :(\n");
            break;

        default:
            std::printf("Unknown standard opcode: 0x%x\n", opcode);
            std::exit(1);
            break;
    }

    ++offset;

    return false;
}

bool Dwarf::get_line_number(unsigned long long rip,
        unsigned int debug_line_offset)
{
    struct debug_line_hdr* debug_line_hdr;
    std::size_t offset = m_debug_line->sh_offset + debug_line_offset;

    debug_line_hdr = reinterpret_cast<struct debug_line_hdr*> (&m_buf[offset]);

    m_reg_is_stmt = debug_line_hdr->default_is_stmt;

    offset = m_debug_line->sh_offset;
    offset += debug_line_offset + debug_line_hdr->prologue_length + 10;

    while (offset < m_debug_line->sh_offset + m_debug_line->sh_size
            && !m_reg_end_sequence)
    {
        unsigned char opcode = m_buf[offset];

        if (opcode == 0)
            handle_extended_opcode(offset);

        // we have a special opcode
        else if (opcode > debug_line_hdr->opcode_base)
        {
            if (handle_special_opcode(offset, debug_line_hdr, rip))
                return true;
        }

        else
            if (handle_standard_opcode(offset, debug_line_hdr, rip))
                return true;
    }

    return false;
}

void Dwarf::print_file_line(unsigned char* comp_dir, unsigned char* file_name)
{
    std::string file_path(reinterpret_cast<char*>(comp_dir));
    std::string file_name_string = reinterpret_cast<char*>(file_name);

    file_path += "/" + file_name_string;

    std::shared_ptr<std::ifstream> file_ptr = m_map_ifstream[file_path];
    file_ptr->seekg(file_ptr->beg);

    const int line_max_size = 4096;
    char line[line_max_size];
    unsigned int n_line = 0;

    while (n_line < m_reg_line && file_ptr->getline(line, line_max_size))
        ++n_line;

    if (n_line == m_reg_line)
        std::printf("%s\n", line);
}

void Dwarf::addr2line_print_instruction(unsigned long long rip,
        struct range_addr& range_addr)
{
    static unsigned int old_line_number = 0;
    reset_registers();

    if (!get_line_number(rip, range_addr.debug_line_offset))
    {
        std::cerr << "Can't find the line corresponding to this instruction.";
        std::cerr << std::endl;
        std::exit(1);
    }

    // we have a line that is composed with more than one cpu instruction
    if (m_reg_line == old_line_number)
        return;

    else
        old_line_number = m_reg_line;

    unsigned char* comp_dir =
        &m_buf[m_debug_str->sh_offset + range_addr.debug_str_comp_dir_offset];

    unsigned char* file_name =
        &m_buf[m_debug_str->sh_offset + range_addr.debug_str_file_name_offset];

    std::cout << std::hex << "0x" << rip << ": ";
    std::printf("%s/%s:%.5d", comp_dir, file_name, m_reg_line);

    std::cout << " | ";
    print_file_line(comp_dir, file_name);
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
