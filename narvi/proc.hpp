// proc.hpp -- tiny subprocess helpers (fork/exec, no shell), shared by the
// rebuilders (mksquashfs) and the CLI (moria orchestration for `narvi init`).
#pragma once
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace narvi {

// True if `prog` is an executable on $PATH, or is itself an executable path.
inline bool on_path(const std::string& prog) {
    if (prog.find('/') != std::string::npos)
        return ::access(prog.c_str(), X_OK) == 0;
    const char* p = getenv("PATH");
    if (!p) return false;
    std::stringstream ss(p);
    std::string dir;
    while (std::getline(ss, dir, ':'))
        if (!dir.empty() && ::access((dir + "/" + prog).c_str(), X_OK) == 0) return true;
    return false;
}

// Run argv directly (no shell). If stdout_path is non-empty, the child's stdout
// is redirected there (truncated). Returns the exit code, or -1 if it did not
// exit normally, or 127 if the program could not be executed.
inline int run(const std::vector<std::string>& argv, const std::string& stdout_path = "") {
    pid_t pid = fork();
    if (pid == 0) {
        if (!stdout_path.empty()) {
            int fd = ::open(stdout_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) _exit(126);
            dup2(fd, 1);
            close(fd);
        }
        std::vector<char*> a;
        for (auto& s : argv) a.push_back(const_cast<char*>(s.c_str()));
        a.push_back(nullptr);
        execvp(a[0], a.data());
        _exit(127);
    }
    if (pid < 0) return -1;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

}  // namespace narvi
