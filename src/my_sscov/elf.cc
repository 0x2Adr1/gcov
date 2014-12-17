#include "my_sscov.hh"
#include "../elf.hh"

void Elf::sscov(std::fstream& stream, const struct user_regs_struct& user_regs)
{
    unsigned long long rip = user_regs.rip;

    if (rip < m_text_shdr->sh_addr
            || rip > m_text_shdr->sh_addr + m_text_shdr->sh_size)
        return;

    stream << "0x" << std::hex << rip << ":";

    unsigned char* opcode = reinterpret_cast<unsigned char*>
        (&m_buf[m_text_shdr->sh_offset + (rip - m_text_shdr->sh_addr)]);

    if ((*opcode) == 0xE8)
        stream << " CALL";

    else if (*opcode == 0xC2 || *opcode == 0xC3)
        stream << " RET";

    else if ((*opcode >= 0xE9 && *opcode <= 0xEB)
            || (*opcode >= 0x70 && *opcode <= 0x7F)
            || (*opcode == 0x0F
                && *(opcode + 1) >= 0x80 && *(opcode + 1) <= 0x8F))
        stream << " JMP\t0x" << user_regs.eflags;

    stream << std::endl;
}
