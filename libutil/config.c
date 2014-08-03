#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"


static const char *whitespace = " \t\n";

static void
strrstrip(char *line, size_t len, const char *delim)
{
    const char *d;
    char *p;

    for (p = line + len - 1; p > line; p--) {
        for (d = delim; *p != *d && *d != '\0'; d++)
            ;

        if (*d == '\0') {
            *(p + 1) = '\0';
            return;
        }
    }
}

int
config_read(FILE *fp, char **keyp, char **valuep, int *lineno)
{
    char *token, *line = NULL;
    char *key, *value;
    size_t len = 0;
    ssize_t nread;

    *keyp = NULL;
    *valuep = NULL;

    do {
        errno = 0;
        if ((nread = getline(&line, &len, fp)) < 0)
            goto err;

        (*lineno)++;

        strrstrip(line, nread, whitespace);
        token = line + strspn(line, whitespace);
        key = strsep(&token, whitespace);

        if (token != NULL)
            value = token + strspn(token, whitespace);
        else
            value = "";
    } while (key[0] == '#' || key[0] == '\0');

    if ((*keyp = strdup(key)) == NULL)
        goto err;
    if ((*valuep = strdup(value)) == NULL)
        goto err;

    free(line);
    return 1;

err:
    free(line);
    free(*keyp);
    free(*valuep);
    return errno == 0 ? 0 : -1;
}
