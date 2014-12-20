#include "../dwarf.hh"

#include <utility>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>

#include <assert.h>

#include <dwarf.h>

Dwarf::Dwarf(unsigned char* buf, Elf64_Shdr* debug_info,
        Elf64_Shdr* debug_str, Elf64_Shdr* debug_aranges,
        Elf64_Shdr* debug_line, Elf64_Shdr* debug_abbrev)
{
    m_debug_info = debug_info;
    m_debug_str = debug_str;
    m_debug_line = debug_line;
    m_debug_aranges = debug_aranges;
    m_debug_abbrev = debug_abbrev;

    m_buf = buf;

    assert(m_debug_info != nullptr);
    assert(m_debug_line != nullptr);
    assert(m_debug_aranges != nullptr);
    assert(m_debug_str != nullptr);
    assert(m_debug_abbrev != nullptr);
    assert(m_buf != nullptr);
}

Dwarf::~Dwarf()
{
}

std::uint64_t Dwarf::get_leb128(std::size_t& offset, bool sign,
        bool modify_offset)
{
    std::uint64_t result = 0;
    std::uint32_t shift = 0;
    unsigned char byte;
    std::size_t offset_backup = offset;

    do
    {
        byte = m_buf[offset++];
        result |= ((std::uint64_t) (byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    if (sign && (shift < 8 * sizeof (result)) && (byte & 0x40))
        result |= -1L << shift;

    if (!modify_offset)
        offset = offset_backup;

    return result;
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

        std::uint64_t* addr_begin = reinterpret_cast<std::uint64_t*>
            (&m_buf[i + m_debug_aranges->sh_offset]);

        i += debug_aranges_hdr->addr_size;

        std::uint32_t* offset = reinterpret_cast<std::uint32_t*>
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

void Dwarf::insert_file_in_map(struct range_addr& range_addr)
{
    unsigned char* comp_dir =
        &m_buf[m_debug_str->sh_offset + range_addr.debug_str_comp_dir_offset];

    unsigned char* file_name =
        &m_buf[m_debug_str->sh_offset + range_addr.debug_str_file_name_offset];

    std::string file_path(reinterpret_cast<char*>(comp_dir));
    std::string file_name_string(reinterpret_cast<char*>(file_name));

    if (file_name_string[0] == '/')
        file_path = file_name_string;

    else
        file_path += "/" + file_name_string;

    m_map_ifstream.insert({file_path, std::make_shared<std::ifstream>(file_path)});

    std::ifstream& file_stream = *m_map_ifstream[file_path];

    std::size_t n_line = 0;
    std::string line;
    while (std::getline(file_stream, line))
        ++n_line;

    file_stream.clear();
    file_stream.seekg(file_stream.beg);

    std::vector<int> vect(n_line + 1, 0);
    m_gcov_vect.insert({file_path, std::move(vect)});
}

std::size_t Dwarf::get_form_size(unsigned char byte, struct debug_info_hdr*
        debug_info_hdr, std::size_t offset)
{
    switch (byte)
    {
    case DW_FORM_strp:
        return 4;

    case DW_FORM_addr:
        return debug_info_hdr->addr_size;

    case DW_FORM_block1:
        return 1;

    case DW_FORM_block2:
        return 2;

    case DW_FORM_block4:
        return 4;

    case DW_FORM_block:
        return get_leb128(offset, false, false);

    case DW_FORM_data1:
        return 1;

    case DW_FORM_data2:
        return 2;

    case DW_FORM_data4:
        return 4;

    case DW_FORM_data8:
        return 8;

    case DW_FORM_sdata:
        return get_leb128(offset, true, false);

    case DW_FORM_udata:
        return get_leb128(offset, false, false);

    case DW_FORM_sec_offset:
        return 4;
    }

    return 0;
}

void Dwarf::get_debug_line_offset(struct range_addr& range_addr)
{
    struct debug_info_hdr* debug_info_hdr;

    std::size_t offset = m_debug_info->sh_offset + range_addr.debug_info_offset;

    debug_info_hdr = reinterpret_cast<struct debug_info_hdr*>
        (&m_buf[offset]);

    offset += sizeof (struct debug_info_hdr) + 1;

    std::size_t i = 3 + m_debug_abbrev->sh_offset + debug_info_hdr->abbrev_offset;

    while (m_buf[i])
    {
        switch (m_buf[i])
        {
        case DW_AT_comp_dir:
            range_addr.debug_str_comp_dir_offset =
                *reinterpret_cast<std::uint32_t*>(&m_buf[offset]);
            break;

        case DW_AT_name:
            range_addr.debug_str_file_name_offset =
                *reinterpret_cast<std::uint32_t*>(&m_buf[offset]);
            break;

        case DW_AT_stmt_list:
            range_addr.debug_line_offset = *reinterpret_cast<std::uint32_t*>
                (&m_buf[offset]);
            break;
        }

        offset += get_form_size(m_buf[i + 1], debug_info_hdr, offset);
        i += 2;
    }

    insert_file_in_map(range_addr);
}

void Dwarf::handle_extended_opcode(std::size_t& offset)
{
    offset++;
    std::size_t length = m_buf[offset++];

    if (length == 0)
    {
        std::cerr << "error: length for extended opcode is null." << std::endl;
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
        m_reg_address = *reinterpret_cast<std::uint64_t*>(&m_buf[offset + 1]);
        m_reg_op_index = 0;
        break;

    case DW_LNE_set_discriminator:
        get_leb128(offset, false, false);
        break;

    case DW_LNE_define_file:
        offset += std::strlen(reinterpret_cast<char*>(&m_buf[offset + 1]));
        get_leb128(offset, false);
        get_leb128(offset, false);
        break;

    default:
        std::printf("Uknown extended opcode 0x%x\n", extended_opcode);
        break;
    }

    offset += length;
}

bool Dwarf::handle_special_opcode(std::size_t& offset,
        struct debug_line_hdr* debug_line_hdr, std::uint64_t rip)
{
    unsigned char adjusted_opcode = m_buf[offset] - debug_line_hdr->opcode_base;
    int op_advance = adjusted_opcode / debug_line_hdr->line_range;

    std::uint64_t tmp_address = m_reg_address;

    m_reg_address += op_advance;

    if (rip >= tmp_address && rip < m_reg_address)
        return true;

    op_advance = adjusted_opcode % debug_line_hdr->line_range;
    op_advance += debug_line_hdr->line_base;
    m_reg_line += op_advance;

    ++offset;

    if (rip == m_reg_address)
        return true;

    return false;
}

bool Dwarf::handle_standard_opcode(std::size_t& offset,
        struct debug_line_hdr* debug_line_hdr, std::uint64_t rip)
{
    unsigned char opcode = m_buf[offset++];
    int op_advance = 0;
    std::uint64_t tmp_address = 0;
    std::uint64_t tmp = 0;

    switch (opcode)
    {
    case DW_LNS_copy:
        break;

    case DW_LNS_advance_pc:
        op_advance = debug_line_hdr->min_inst_length;
        op_advance *= get_leb128(offset, false);
        tmp_address = m_reg_address;
        m_reg_address += op_advance;
        if (rip >= tmp_address && rip < m_reg_address)
            return true;

        break;

    case DW_LNS_advance_line:
        op_advance = get_leb128(offset, true);
        m_reg_line += op_advance;
        break;

    case DW_LNS_set_file:
        op_advance = get_leb128(offset, false);
        m_reg_file = op_advance;
        break;

    case DW_LNS_negate_stmt:
        m_reg_is_stmt = !m_reg_is_stmt;
        break;

    case DW_LNS_const_add_pc:
        tmp_address = m_reg_address;

        tmp = 255 - debug_line_hdr->opcode_base;
        tmp /= debug_line_hdr->line_range;
        tmp *= debug_line_hdr->min_inst_length;

        m_reg_address += tmp;

        if (rip >= tmp_address && rip < m_reg_address)
            return true;

        break;

    case DW_LNS_fixed_advance_pc:
        op_advance = *reinterpret_cast<std::uint16_t*>(&m_buf[offset]);
        offset += 2;
        m_reg_address += op_advance;
        break;

    default:
        offset += debug_line_hdr->standard_opcode_lengths[opcode - 1];
        std::printf("Unknown standard opcode: 0x%x\n", opcode);
        break;
    }

    return false;
}

bool Dwarf::get_line_number(std::uint64_t rip,
        std::uint32_t debug_line_offset)
{
    struct debug_line_hdr* debug_line_hdr;
    std::size_t offset = m_debug_line->sh_offset + debug_line_offset;

    debug_line_hdr = reinterpret_cast<struct debug_line_hdr*> (&m_buf[offset]);

    m_reg_is_stmt = debug_line_hdr->default_is_stmt;

    offset = m_debug_line->sh_offset;
    offset += debug_line_offset + debug_line_hdr->prologue_length + 10;

    std::size_t max_offset = m_debug_line->sh_offset + debug_line_offset + 4;
    max_offset += debug_line_hdr->length;
    while (offset < max_offset)
    {
        unsigned char opcode = m_buf[offset];

        if (opcode == 0x00)
            handle_extended_opcode(offset);

        // we have a special opcode
        else if (opcode >= debug_line_hdr->opcode_base)
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

    if (file_name_string[0] == '/')
        file_path = file_name_string;

    else
        file_path += "/" + file_name_string;

    std::shared_ptr<std::ifstream> file_ptr = m_map_ifstream[file_path];
    file_ptr->clear();
    file_ptr->seekg(file_ptr->beg);

    std::string line;
    std::size_t n_line = 0;

    while (n_line < m_reg_line && std::getline(*file_ptr, line))
        ++n_line;

    if (n_line == m_reg_line)
        std::cout << line;

    std::cout << std::endl;
}

void Dwarf::addr2line_print_instruction(std::uint64_t rip,
        struct range_addr& range_addr)
{
    static std::uint32_t old_line_number = 0;
    reset_registers();

    if (!get_line_number(rip, range_addr.debug_line_offset))
    {
        std::cerr << "Can't find the line corresponding to this instruction.";
        std::cerr << std::endl << "(0x" << std::hex << rip << ")" << std::endl;
        std::cerr << std::endl;
        return;
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

    if (file_name[0] == '/')
        std::printf("%s:%.5d", file_name, m_reg_line);

    else
        std::printf("%s/%s:%.5d", comp_dir, file_name, m_reg_line);

    std::cout << " | ";
    print_file_line(comp_dir, file_name);
}

void Dwarf::addr2line(const struct user_regs_struct& user_regs)
{
    std::uint64_t rip = user_regs.rip;

    for (auto& elt : m_list_range)
    {
        if (rip >= elt.begin && rip < (elt.begin + elt.offset))
        {
            addr2line_print_instruction(rip, elt);
            return;
        }
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
