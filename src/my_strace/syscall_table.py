#! /usr/bin/env python3

import sys

def main():
    if len(sys.argv) != 2:
        print("Usage: ./syscall_table.py /path/to/unistd_64.h")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        file_content = f.read()

        index_first_define_syscall = file_content.find('#define __NR_')

        file_content = file_content[index_first_define_syscall:]

        l = file_content.split('#define __NR_')

        with open('syscall_name.hh', 'w') as f_out:
            f_out.write('#ifndef SYSCALL_NAME_HH\n')
            f_out.write('# define SYSCALL_NAME_HH\n')
            f_out.write('\n# define SYSCALL_NAME() \\\n')
            for e in l:
                syscall_name = e.split()
                if len(syscall_name) > 0:
                    f_out.write('    "' + syscall_name[0] + '", \\\n')
            f_out.write('\n#endif /* !SYSCALL_NAME_HH\n')

if __name__ == '__main__':
    main()
