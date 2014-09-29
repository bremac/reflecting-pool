#define _GNU_SOURCE

#include <sys/types.h>

#include <err.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include "util.h"


void
setuser(const char *username)
{
    struct passwd *pw;
    struct group *grp;

    if ((pw = getpwnam(username)) == NULL)
        err(1, "no user found with name %s", username);

    if ((grp = getgrgid(pw->pw_gid)) == NULL)
        err(1, "no group found with gid %d", pw->pw_gid);

    if (setgroups(1, &pw->pw_gid) ||
        setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
        setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
        err(1, "failed to drop privileges");

    log_msg("running as user %s in group %s", pw->pw_name, grp->gr_name);
}
