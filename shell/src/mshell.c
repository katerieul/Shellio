#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include "config.h"
#include "siparse.h"
#include "builtins.h"

struct sigaction defaultsigintaction;
sigset_t sigchildset;
int is_atty;

struct background_pid_history {
    pid_t pids[MAX_HISTORY_LENGTH];
    int signals[MAX_HISTORY_LENGTH];
    int size;
} background_pid_history;

struct foreground_pid_history {
    pid_t pids[MAX_HISTORY_LENGTH];
    int size;
} foreground_pid_history;

void init_history() {
    background_pid_history.size = 0;
    foreground_pid_history.size = 0;
}

void add_pid_to_background_history(int pid, int signal) {
    background_pid_history.pids[background_pid_history.size] = pid;
    background_pid_history.signals[background_pid_history.size++] = signal;
}

void add_pid_to_foreground_history(int pid) {
    foreground_pid_history.pids[foreground_pid_history.size++] = pid;
}

int remove_from_foreground_history(int pid) {
    for (int i = 0; i < foreground_pid_history.size; ++i) {
        if (foreground_pid_history.pids[i] == pid) {
            foreground_pid_history.pids[i] = foreground_pid_history.pids[--foreground_pid_history.size];
            return 1;
        }
    }
    return 0;
}

void handle_exit(int pid, int status) {
    dprintf(STDOUT_FILENO, "Background process %d terminated. (exited with status %d)\n", pid, status);
    // fflush(stdout);
}

void handle_kill(int pid, int status) {
    dprintf(STDOUT_FILENO, "Background process %d terminated. (killed by signal %d)\n", pid, status);
    // fflush(stdout);
}

void check_for_errors(int status, const char *object) {
    if (status == -1) {
        if (errno == ENOENT)
            dprintf(STDERR_FILENO, "%s: %s\n", object, "no such file or directory");
        else if (errno == EACCES)
            dprintf(STDERR_FILENO, "%s: %s\n", object, "permission denied");
        // fflush(stderr);
        exit(EXIT_FAILURE);
    }
}

void sigint_handler() {
    int pid, sig, lasterr = errno;
    while ((pid = waitpid(-1, &sig, WNOHANG)) > 0)
        if (!remove_from_foreground_history(pid) && is_atty)
            add_pid_to_background_history(pid, sig);
    errno = lasterr;
}

void init_sigactions() {
    struct sigaction childaction;
    childaction.sa_handler = sigint_handler;
    childaction.sa_flags = SA_RESTART;
    sigemptyset(&childaction.sa_mask);
    sigaction(SIGCHLD, &childaction, NULL);

    struct sigaction sigintaction;
    sigintaction.sa_handler = SIG_IGN;
    sigintaction.sa_flags = SA_RESTART;
    sigemptyset(&sigintaction.sa_mask);
    sigaction(SIGINT, &sigintaction, &defaultsigintaction);

    sigemptyset(&sigchildset);
    sigaddset(&sigchildset, SIGCHLD);
}

int process_builtin_command(char *arg[]) {
    for (int i = 0; builtins_table[i].name; i++) {
        if (!strcmp(arg[0], builtins_table[i].name)) {
            if (builtins_table[i].fun(arg) == BUILTIN_ERROR) {
                dprintf(STDERR_FILENO, "Builtin %s error.\n", builtins_table[i].name);
                // fflush(stderr);
            }
            return 1;
        }
    }
    return 0;
}

void run_child(char *arg_array[]) {
    if (execvp(arg_array[0], arg_array) == -1) {
        dprintf(STDERR_FILENO, "%s: ", arg_array[0]);
        if (errno == EACCES)
            dprintf(STDERR_FILENO, "%s", PERMISSION_DENIED);
        else if (errno == ENOENT)
            dprintf(STDERR_FILENO, "%s", NO_SUCH_FILE);
        else
            dprintf(STDERR_FILENO, "%s", EXEC_ERROR);
        // fflush(stderr);
        exit(EXIT_FAILURE);
    } else
        exit(EXIT_SUCCESS); // I don't think it can happen but ...
}

void parse_args(char *arg_array[], command *com) {
    argseq *args = com->args;
    int i = 0;
    for (; i == 0 || args != com->args; i++, args = args->next)
        arg_array[i] = args->arg;
    arg_array[i] = NULL;
}

size_t get_commands_count(commandseq *commands) {
    size_t cnt = 0;

    commandseq *current_command = commands;
    do {
        current_command = current_command->next;
        cnt++;
    } while (current_command != commands);

    return cnt;
}

void process_pipeline(pipeline *pipeln) {
    if (!pipeln)
        return;
    commandseq *commands = pipeln->commands;
    if (!commands || !commands->com)
        return;

    sigprocmask(SIG_BLOCK, &sigchildset, NULL);

    int pipefds_prev[2], pipefds_next[2];
    commandseq *current_command = commands;
    size_t commands_count = get_commands_count(commands);
    for (int i = 0; i < commands_count; ++i, current_command = current_command->next) {
        command *com = current_command->com;
        if (i != commands_count - 1)
            if (pipe(pipefds_next))
                exit(EXIT_FAILURE);

        char *arg_array[MAX_LINE_LENGTH / 2 + 5];
        parse_args(arg_array, com);

        if (!process_builtin_command(arg_array)) {
            int pid = fork();
            if (pid == 0) { // child
                if (pipeln->flags & INBACKGROUND)
                    setsid();
                sigaction(SIGINT, &defaultsigintaction, NULL);

                // dup prev
                if (i) {
                    dup2(pipefds_prev[0], STDIN_FILENO);
                    close(pipefds_prev[0]);
                }

                // dup next
                if (i != commands_count - 1) {
                    dup2(pipefds_next[1], STDOUT_FILENO);
                    close(pipefds_next[1]);
                }

                close(pipefds_next[0]);

                redirseq *redirs = com->redirs;
                int stdin_fd = 0;
                int stdout_fd = 0;
                if (redirs) {
                    do {
                        if (!redirs->r)
                            break;
                        int flags = redirs->r->flags;
                        if (IS_RIN(flags)) {
                            stdin_fd = open(redirs->r->filename, O_RDONLY, S_IRWXU);
                            dprintf(STDOUT_FILENO, "%d\n", stdin_fd);
                        }
                        check_for_errors(stdin_fd, redirs->r->filename);

                        if (stdin_fd != STDIN_FILENO) {
                            dup2(stdin_fd, STDIN_FILENO);
                            close(stdin_fd);
                        }

                        if (IS_RAPPEND(flags))
                            stdout_fd = open(redirs->r->filename, O_CREAT | O_WRONLY | O_APPEND, S_IRWXU);
                        else if (IS_ROUT(flags))
                            stdout_fd = open(redirs->r->filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
                        check_for_errors(stdout_fd, redirs->r->filename);

                        if (stdout_fd != STDOUT_FILENO) {
                            dup2(stdout_fd, STDOUT_FILENO);
                            close(stdout_fd);
                        }

                        redirs = redirs->next;
                    } while (redirs != com->redirs);
                }

                run_child(arg_array);
            }
            if (!(pipeln->flags & INBACKGROUND))
                add_pid_to_foreground_history(pid);
            if (i)
                close(pipefds_prev[0]);
            if (i != commands_count - 1)
                close(pipefds_next[1]);
            pipefds_prev[0] = pipefds_next[0];
            pipefds_prev[1] = pipefds_next[1];
        }
    }
    sigprocmask(SIG_UNBLOCK, &sigchildset, NULL);

    if (!(pipeln->flags & INBACKGROUND)) {
        sigset_t set;
        sigprocmask(SIG_BLOCK, &sigchildset, &set);
        while (foreground_pid_history.size)
            sigsuspend(&set);
        sigprocmask(SIG_SETMASK, &set, NULL);
    }
}

void process_buffer(char *buf) {
    pipelineseq *ln = parseline(buf);
    if (!ln) {
        dprintf(STDERR_FILENO, "%s\n", SYNTAX_ERROR_STR);
//        fflush(stderr);
    } else {
        pipelineseq *pipelines = ln;
        do {
            process_pipeline(pipelines->pipeline);
            pipelines = pipelines->next;
        } while (pipelines != ln);
    }
}

size_t readstdin(char *buf) {
    size_t size = 0;
    while (size <= MAX_LINE_LENGTH) {
        long int status = read(STDIN_FILENO, buf + size, 1);
        if (status == -1)
            return -1;
        if (buf[size] == '\n') {
            buf[size] = '\0';
            break;
        }
        if (status == 0) {
            if (size == 0)
                return 0;
            else
                break;
        }
        ++size;
    }
    if (size > MAX_LINE_LENGTH) {
        while (read(STDIN_FILENO, buf, 1) > 0 && buf[0] != '\n') {}
        dprintf(STDERR_FILENO, "%s\n", SYNTAX_ERROR_STR);
        // fflush(stderr);
        return -1;
    }
    return size + 1;
}

void close_background_tasks() {
    sigprocmask(SIG_BLOCK, &sigchildset, NULL);
    for (int i = 0; i < background_pid_history.size; ++i) {
        int signal = background_pid_history.signals[i];
        if (WIFEXITED(signal))
            handle_exit(background_pid_history.pids[i], WEXITSTATUS(signal));
        else if (WIFSIGNALED(signal))
            handle_kill(background_pid_history.pids[i], WTERMSIG(signal));
    }
    background_pid_history.size = 0;
    sigprocmask(SIG_UNBLOCK, &sigchildset, NULL);
}

int main() {
    char buf[MAX_LINE_LENGTH + 2];
    init_history();
    init_sigactions();
    is_atty = isatty(STDIN_FILENO);
    while (1) {
        if (is_atty) {
            close_background_tasks();
            dprintf(STDOUT_FILENO, "%s", PROMPT_STR);
//            fflush(stdout);
        }
        size_t buf_size = readstdin(buf);
        if (buf_size == 0)
            break;
        if (buf_size == -1)
            continue;
        process_buffer(buf);
    }

    exit(EXIT_SUCCESS);
}