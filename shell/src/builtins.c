#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <config.h>
#include <dirent.h>
#include "builtins.h"

int shecho(char *[]);

int shexit(char *[]);

int shlcd(char *[]);

int shkiller(char *[]);

int shls(char *[]);

builtin_pair builtins_table[] = {
        {"exit",  &shexit},
        {"lecho", &shecho},
        {"lcd",   &shlcd},
        {"lkill", &shkiller},
        {"lls",   &shls},
        {NULL, NULL}
};

int shecho(char *argv[]) {
    int i = 1;
    if (argv[i]) printf("%s", argv[i++]);
    while (argv[i])
        printf(" %s", argv[i++]);

    printf("\n");
    fflush(stdout);
    return 0;
}

int shexit(char *argv[]) {
    exit(EXIT_SUCCESS);
}

int shlcd(char *argv[]) {
    int result;
    if (argv[2])
        return BUILTIN_ERROR;
    if (argv[1])
        result = chdir(argv[1]);
    else
        result = chdir(getenv("HOME"));
    if (result == -1)
        return BUILTIN_ERROR;
    return 0;
}

int shkiller(char *argv[]) {
    if (!argv[1])
        return BUILTIN_ERROR;
    int pid;
    long pid1, sig1;
    int sig = SIGTERM;
    if (argv[2]) {
        if (argv[1][0] != '-')
            return BUILTIN_ERROR;
        pid1 = strtol(argv[2], (char**)NULL, 10);
        if ((char**NULL) == argv[2]) {
            perror("Invalid format");
        } else if ('\0' != (char**)NULL) {
            perror("Extra characters at the end of input");
        } else if ((LONG_MIN == pid1 || LONG_MAX == pid1) && ERANGE == errno) {
            perror("Out of long's range");
        } else if (pid1 > INT_MAX) {
            perror("Greater than INT_MAX");
        } else if (pid1 < INT_MIN) {
            perror("Less than INT_MIN");
        } else {
            pid = (int)pid1;
        }
        sig1 = strtol(argv[1] + 1, (char**)NULL, 10);
        if ((char**NULL) == argv[1] + 1) {
            perror("Invalid format");
        } else if ('\0' != (char**)NULL) {
            perror("Extra characters at the end of input");
        } else if ((LONG_MIN == sig1 || LONG_MAX == sig1) && ERANGE == errno) {
            perror("Out of long's range");
        } else if (sig1 > INT_MAX) {
            perror("Greater than INT_MAX");
        } else if (sig1 < INT_MIN) {
            perror("Less than INT_MIN");
        } else {
            sig = (int)sig1;
        }
    } else {
        pid1 = strtol(argv[1], (char**)NULL, 10);
        if ((char**NULL) == argv[1]) {
            perror("Invalid format");
        } else if ('\0' != (char**)NULL) {
            perror("Extra characters at the end of input");
        } else if ((LONG_MIN == pid1 || LONG_MAX == pid1) && ERANGE == errno) {
            perror("Out of long's range");
        } else if (pid1 > INT_MAX) {
            perror("Greater than INT_MAX");
        } else if (pid1 < INT_MIN) {
            perror("Less than INT_MIN");
        } else {
            pid = (int)pid1;
        }
    }
    if (kill((pid_t) pid, sig) == -1)
        return BUILTIN_ERROR;
    return 0;
}

int shls(char *argv[]) {
    char cwd[MAX_LINE_LENGTH];
    if (getcwd(cwd, MAX_LINE_LENGTH)) {
        DIR *dir = opendir(cwd);
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
            if (entry->d_name[0] != '.')
                fprintf(stdout, "%s\n", entry->d_name);
        fflush(stdout);
    }
    return 0;
}
