/*
 * libnss_ato.c
 *
 * Nss module to map every requested user to a fixed one.
 * Ato stands for "All To One"
 *
 * Copyright (c) Pietro Donatini (pietro.donatini@unibo.it), 2007.
 *
 * this product may be distributed under the terms of
 * the GNU Lesser Public License.
 *
 * version 0.2
 *
 * CHANGELOG:
 * strip end of line in reading /etc/libnss-ato
 * suggested by Kyler Laird
 *
 * TODO:
 *
 * check bugs
 *
 */

#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

/*
 * Match to the list of process names for which this module should return a
 * result.
 * They are processes which call nss_ato on login, and user-run OS command line
 * programs.
 */
const char *VALID_PROC_NAMES[] = {"sshd",
                                  "login",
				  // SSHd on CentOS uses "unix_chkpwd", so ato
				  // needs to respond to that
                                  "unix_chkpwd",
				  // The "id" program isn't necessary, but it's
				  // useful for testing that the library is set
				  // up correctly, and the README examples
				  // don't work without it.
                                  "id"};

/*
 * Array length macro
 * The size of the whole array divided by the size of the 1st element is the
 * length of the array
 */
#define arraylen(array) ((sizeof(array))/(sizeof(array[0])))

#define FALSE 0
#define TRUE 1

/*
 * Upper limit on the number of lines we'll read from the config file.
 */
#define MAX_CONF_LINES 32

/* for security reasons */
#define MIN_UID_NUMBER   500
#define MIN_GID_NUMBER   500
#define CONF_FILE "/etc/libnss-ato.conf"

/*
 * The configuration /etc/libnss-ato.conf is a series of lines of
 * with the local user data as in /etc/passwd. For example:
 * dona:x:1001:1001:P D ,,,:/home/dona:/bin/bash
 * Lines starting with # are comments (not processed).
 *
 * The function fills in the passed in conf_array with passwd structures, each
 * containing the parsed versions of one line of config. The return value is
 * the number of passwd structures filled in, or 0 if there has been an error.
 *
 * There is an upper limit of MAX_CONF_LINES lines that this function will
 * read. The passed in buffer must contain enough space to store at least
 * this many passwd structures.
 */
int read_conf(struct passwd *conf_array)
{
  FILE *fd;
  int line;
  int num_users = 0;
  struct passwd *parsed_conf;
  struct passwd *real_conf;
  int char_check;

	if ((fd = fopen(CONF_FILE, "r")) == NULL ) {
		return 0;
	}

  for (line = 0; line < MAX_CONF_LINES; line++)
  {
    char_check = getc(fd);
    if ((char)char_check == '#')
      /* Lines that start with a # are comments. Ignore them. */
      continue;
    else if (char_check == EOF)
      /* There are no more lines to parse! */
      break;
    else
      /*
       * Because the first character isn't a #, we want to parse this line.
       * Push the character back onto the stream so we can read it normally.
       */
      ungetc(char_check, fd);

    /* Parse the config file. We can't assume that the contents of this file
     * are completely accurate, but they should give us the information we need
     * to extract accurate information from the real /etc/passwd file later.
     */
    parsed_conf = fgetpwent(fd);

    /*
     * For security reasons, we don't allow the UID or GID to be lower than
     * MIN_UID/GID_NUMBER.
     */
    if ( parsed_conf->pw_uid < MIN_UID_NUMBER )
      parsed_conf->pw_uid = MIN_UID_NUMBER;

    if ( parsed_conf->pw_gid < MIN_GID_NUMBER )
      parsed_conf->pw_gid = MIN_GID_NUMBER;

    /*
     * Now we've got the UID to match to, get the full entry from
     * /etc/passwd. This means we don't need to specify the right home
     * directory in our conf file.
     */
    real_conf = getpwuid(parsed_conf->pw_uid);
    if (real_conf)
    {
      memcpy(&conf_array[num_users],
             real_conf,
             sizeof(struct passwd));
      num_users++;
    }
    else
    {
      /*
       * There's a problem with the config file! The parsed UID doesn't match
       * any users on the system.
       */
      return 0;
    }
  }

  fclose(fd);

  return num_users;
}

/*
 * Allocate some space from the nss static buffer.  The buffer and buflen
 * are the pointers passed in by the C library to the _nss_ntdom_*
 * functions.
 *
 *  Taken from glibc
 */

static char *
get_static(char **buffer, size_t *buflen, int len)
{
	char *result;

	/* Error check.  We return false if things aren't set up right, or
         * there isn't enough buffer space left. */

	if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
		return NULL;
	}

	/* Return an index into the static buffer */

	result = *buffer;
	*buffer += len;
	*buflen -= len;

	return result;
}

/*
 * An environment variable (USER_LOGIN) should have been set to indicate which
 * user we should be mapping to. If it isn't, we should select the first user
 * on the list.
 */
struct passwd *
select_user(int num_users, struct passwd *user_list)
{
  char *env_user_name = getenv("USER_LOGIN");
  struct passwd *user;
  int user_index;

  syslog(LOG_AUTH|LOG_NOTICE, "libnss_ato: USER_LOGIN: %s", env_user_name);

  if (env_user_name == NULL)
    /*
     * No environment variable has been set. Just use the first entry in the
     * list. Note that we should be able to guarantee that there's at least
     * one entry in the user list by the point this function is called.
     */
    return &user_list[0];

  for (user_index = 0; user_index < num_users; user_index++)
  {
    user = &user_list[user_index];
    if (!strncmp(env_user_name, user->pw_name, strlen(env_user_name)))
    {
      /* We've found the user we're looking for! */
      syslog(LOG_AUTH, "libnss_ato: Found user %s", user->pw_name);
      return user;
    }
    syslog(LOG_AUTH, "libnss_ato: User %s didn't match", user->pw_name);
  }

  /*
   * None of the configured users match the environment variable. In this case
   * we return the first value on the list.
   */
  syslog(LOG_AUTH, "libnss_ato: Didn't find user");
  return &user_list[0];
}

/*
 * should_find_user
 * This determines whether this module should return 'not found' for the user,
 * based on the name of the process it's being called in.
 * The module should return the user only it is being called as part of a
 * login attempt (over ssh or the console) or by some OS command-line
 * programs.
 *
 * This function returns a boolean.
 */
int should_find_user(void)
{
  FILE *fd;
  /*
   * On Linux use the stat file to get the process name
   */
  char proc_file[] = "/proc/self/stat";
  int pid;

  /* Open the file */
  if ((fd = fopen(proc_file, "r")) == NULL )
  {
    return FALSE;
  }

  /* Read the process ID */
  fscanf(fd, "%d ", &pid);

  /*
   * Read the process name, which is at most 16 characters and enclosed in
   * brackets.
   */
  char name[17];
  fscanf(fd, "(%16[^)])", name);
  fclose(fd);

  /*
   * Match to the list of permitted process names, defined at the top of the
   * file.
   */
  int i;
  for (i = 0; i < arraylen(VALID_PROC_NAMES); i++) {
    if (strcmp(name, VALID_PROC_NAMES[i]) == 0) {
      syslog(LOG_AUTH|LOG_NOTICE, "libnss_ato: Process name matched '%s'", VALID_PROC_NAMES[i]);
      return TRUE;
    }
  }

  // Process name didn't match any that we want.
  syslog(LOG_AUTH|LOG_NOTICE, "libnss_ato: libnss_ato is not set to return mapping to process '%s'", name);
  return FALSE;
}

enum nss_status
_nss_ato_getpwnam_r( const char *name,
                    struct passwd *p,
                    char *buffer,
                    size_t buflen,
                    int *errnop)
{
	struct passwd *conf_array;

  if (!should_find_user())
  {
    syslog(LOG_AUTH|LOG_NOTICE, "libnss_ato: Not mapping user '%s' to default user", name);
    return NSS_STATUS_NOTFOUND;
  }

  /* Dynamically assign some memory to use for storing config from file. */
  conf_array = (struct passwd *)malloc(sizeof(struct passwd) * MAX_CONF_LINES);
  int num_users = read_conf(conf_array);

  /* We can't go any further if we didn't manage to parse any users out of the
   * config file.
   */
  if (!num_users) {
    free(conf_array);
    return NSS_STATUS_NOTFOUND;
  }

  /* Find the user we want to map to from the config file. */
  *p = *select_user(num_users, conf_array);
  syslog(LOG_AUTH|LOG_NOTICE,
             "libnss_ato: Mapping user '%s' to locally provisioned user '%s'",
             name,
             p->pw_name);

  /* We've got all we need from the configuration file at this point. */
  free(conf_array);

	/* If out of memory */
	if ((p->pw_name = get_static(&buffer, &buflen, strlen(name) + 1)) == NULL) {
		return NSS_STATUS_TRYAGAIN;
	}

	/* pw_name stay as the name given */
	strcpy(p->pw_name, name);

	if ((p->pw_passwd = get_static(&buffer, &buflen, strlen("x") + 1)) == NULL) {
                return NSS_STATUS_TRYAGAIN;
        }

	strcpy(p->pw_passwd, "x");

	return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_ato_getspnam_r( const char *name,
                     struct spwd *s,
                     char *buffer,
                     size_t buflen,
                     int *errnop)
{
  if (!should_find_user())
  {
    syslog(LOG_AUTH|LOG_NOTICE, "libnss_ato: Not mapping user '%s' to default user", name);
    return NSS_STATUS_NOTFOUND;
  }

  /* If out of memory */
  if ((s->sp_namp = get_static(&buffer, &buflen, strlen(name) + 1)) == NULL) {
          return NSS_STATUS_TRYAGAIN;
  }

  strcpy(s->sp_namp, name);

  if ((s->sp_pwdp = get_static(&buffer, &buflen, strlen("*") + 1)) == NULL) {
          return NSS_STATUS_TRYAGAIN;
  }

  strcpy(s->sp_pwdp, "*");

  s->sp_lstchg = 13571;
  s->sp_min    = 0;
  s->sp_max    = 99999;
  s->sp_warn   = 7;

  syslog(LOG_AUTH|LOG_NOTICE, "libnss_ato: Mapping user '%s' to default user", name);
  return NSS_STATUS_SUCCESS;
}
