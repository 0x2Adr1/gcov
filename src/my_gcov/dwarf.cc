#include "../dwarf.hh"

#include <iostream>
#include <cstdio>

void Dwarf::gcov(std::uint64_t rip)
{
    for (auto& elt : m_list_range)
        if (rip >= elt.begin && rip < (elt.begin + elt.offset))
        {
            gcov_incr_line_count(rip, elt);
            return;
        }
}

void Dwarf::gcov_incr_line_count(std::uint64_t rip,
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

    if (m_reg_line == old_line_number)
        return;

    else
        old_line_number = m_reg_line;

    unsigned char* comp_dir =
        &m_buf[m_debug_str->sh_offset + range_addr.debug_str_comp_dir_offset];

    unsigned char* file_name =
        &m_buf[m_debug_str->sh_offset + range_addr.debug_str_file_name_offset];

    std::string file_path(reinterpret_cast<char*>(comp_dir));
    std::string file_name_string(reinterpret_cast<char*>(file_name));
    file_path += "/" + file_name_string;

    ++m_gcov_vect[file_path][m_reg_line - 1];
}

void Dwarf::print_result_gcov()
{
    for (auto& elt : m_gcov_vect)
    {
        std::shared_ptr<std::ifstream> file_ptr = m_map_ifstream[elt.first];
        file_ptr->seekg(file_ptr->beg);
        std::string line;

        std::cout << elt.first << '\n' << std::endl;

        for (std::size_t i = 1; std::getline(*file_ptr, line); ++i)
        {
            if (elt.second[i - 1] == 0)
                std::cout << "-:\t";

            else
                std::cout << elt.second[i - 1] << ":\t";

            std::printf("%.4lu:", i);
            std::cout << line << std::endl;
        }
    }
}
