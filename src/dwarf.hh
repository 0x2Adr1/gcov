#ifndef DWARF_HH
# define DWARF_HH

# include <list>
# include <fstream>
# include <memory>
# include <vector>
# include <string>
# include <unordered_map>
# include <elf.h>

# include <sys/user.h>

struct debug_info_hdr
{
    std::uint32_t length;
    std::uint16_t version;
    std::uint32_t abbrev_offset;
    unsigned char addr_size;
} __attribute__ ((__packed__));

struct debug_aranges_hdr
{
    unsigned int length;
    unsigned short version;
    unsigned int debug_info_offset;
    unsigned char addr_size;
    unsigned char seg_size;
} __attribute__ ((__packed__));

struct debug_line_hdr
{
    std::uint32_t length;
    std::uint16_t version;
    std::uint32_t prologue_length;
    unsigned char min_inst_length;
    //unsigned char max_inst_length;
    unsigned char default_is_stmt;
    char line_base;
    unsigned char line_range;
    unsigned char opcode_base;
    unsigned char standard_opcode_lengths[12];

} __attribute__ ((__packed__));

struct range_addr
{
    unsigned long long begin;
    unsigned long long offset;
    unsigned int debug_info_offset;
    unsigned int debug_line_offset;
    unsigned int debug_str_file_name_offset;
    unsigned int debug_str_comp_dir_offset;
};

class Dwarf
{
public:
    // buf contains the elf file
    Dwarf(unsigned char* buf, Elf64_Shdr* debug_info, Elf64_Shdr* debug_str,
            Elf64_Shdr* debug_aranges, Elf64_Shdr* debug_line,
            Elf64_Shdr* debug_abbrev);

    ~Dwarf();

    // cu = compilation unit
    void map_range_addr_to_cu();

    void get_debug_line_offset(struct range_addr&);
    void addr2line(const struct user_regs_struct& user_regs);
    void addr2line_print_instruction(unsigned long long rip,
            struct range_addr&);

    void gcov(std::uint64_t vaddr);
    void gcov_incr_line_count(std::uint64_t rip, struct range_addr&);
    void print_result_gcov();

    std::uint64_t get_leb128(std::size_t& offset, bool sign,
            bool modify_offset = true);

private:
    void handle_extended_opcode(std::size_t& offset);
    bool handle_special_opcode(std::size_t& offset, struct debug_line_hdr*,
            unsigned long long rip);
    bool handle_standard_opcode(std::size_t& offset, struct debug_line_hdr*,
            unsigned long long rip);

    void print_file_line(unsigned char* comp_dir, unsigned char* file_name);

    void reset_registers();
    bool get_line_number(unsigned long long rip,
            unsigned int debug_line_offset);

    void insert_file_in_map(struct range_addr& range_addr);

    std::list<range_addr> m_list_range;

    unsigned char* m_buf;

    Elf64_Shdr* m_debug_info;
    Elf64_Shdr* m_debug_str;
    Elf64_Shdr* m_debug_aranges;
    Elf64_Shdr* m_debug_line;
    Elf64_Shdr* m_debug_abbrev;

    unsigned long long m_reg_address;
    unsigned int m_reg_op_index;
    unsigned int m_reg_file;
    unsigned int m_reg_line;
    unsigned int m_reg_column;
    unsigned int m_reg_is_stmt;
    unsigned int m_reg_basic_block;
    unsigned int m_reg_end_sequence;
    unsigned int m_reg_prologue_end;
    unsigned int m_reg_epilogue_begin;
    unsigned int m_reg_isa;
    unsigned int m_reg_discriminator;

    // map a file with an fstream object for fast retrieval in print_file_line()
    std::unordered_map<std::string, std::shared_ptr<std::ifstream> >
        m_map_ifstream;

    std::unordered_map<std::string, std::vector<int> > m_gcov_vect;
};

#endif /* !DWARF_HH */
