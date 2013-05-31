#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

extern char **environ;

int
main(int argc, char **argv)
{
	int i;
	char *buf = NULL;
	size_t bufsize = 128;

	for (;;) {
		char *cwd;

		errno = 0;
		buf = malloc(bufsize);
		if (!buf) {
			fprintf(stderr, "%s: not enough memory\n", argv[0]);
			break;
		}
		if (getcwd(buf, bufsize))
			break;
		free(buf);
		if (errno != ERANGE) {
			fprintf(stderr, "%s: ", argv[0]);
			perror("getcwd");
			buf = NULL;
			break;
		}

		bufsize += bufsize / 16;
		bufsize += 32;
	}
	printf("# Dump of execution environment\n");
	if (buf)
		printf("cwd is %s\n", buf);
	printf("# Arguments\n");
	for (i = 0; i < argc; i++)
		printf("argv[%d]=%s\n", i, argv[i]);
	printf("# Environment\n");
	for (i = 0; environ[i]; i++)
		printf("%s\n", environ[i]);
	printf("# End\n");
	return 0;
}
	
