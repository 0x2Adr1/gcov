#include <sys/types.h> // pid_t
#include <sys/ptrace.h> // ptrace()
#include <cstdlib> // exit()

#include <unistd.h> // fork()

#include "my_strace.hh"

static void handle_syscall(pid_t pid_child)
{

}

static void trace_child(pid_t pid_child)
{
    int status = 0;
    waitpid(pid_child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid_child, 0, PTRACE_O_TRACESYSGOOD);

    while (handle_syscall(pid_child))
    {
        //PTRACE_PEEKUSER allow us to read child registers
        int syscall = ptrace(PTRACE_PEEKUSER, pid_child,
                sizeof (long) * ORIG_EAX);
    }
}

void my_strace(const std::string& bin_path, char *argv[])
{
    pid_t pid_child = fork();

    if (pid_child == -1)
    {
        std::cerr << "FORK ERROR" << std::endl;
        std::exit(1);
    }

    else if (pid_child == 0)
    {
        ptrace(PT_TRACE_ME);
        pid_child = getpid();
        kill(pid_child, SIGSTOP);

        const char *bin_argv[] =
        {
            bin_path.c_str(),
            NULL
        };

        return execvp(bin_path.c_str(), bin_argv);
    }

    else
        trace_child(pid_child);
}
