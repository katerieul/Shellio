#ifndef _BUILTINS_H_
#define _BUILTINS_H_
#define NO_SUCH_FILE "no such file or directory\n"
#define PERMISSION_DENIED "permission denied\n"
#define EXEC_ERROR "exec error\n"
#define BUILTIN_ERROR 2

#define MAX_BUF_LENGTH (MAX_LINE_LENGTH + 2)
typedef struct {
	char* name;
	int (*fun)(char**); 
} builtin_pair;

extern builtin_pair builtins_table[];

#endif /* !_BUILTINS_H_ */
