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
 * The configuration /etc/libnss-ato.conf is a series of lines of
 * with the local user data as in /etc/passwd. For example:
 * dona:x:1001:1001:P D ,,,:/home/dona:/bin/bash
 * Lines starting with # are comments (not processed).
 *
 * The function returns a null-terminated array of user names, one for each
 * line of config.
 *
 * There is an upper limit of MAX_CONF_LINES lines that this function will
 * read. The passed in buffer must contain enough space to store at least
 * this many usernames.
 */
char **read_conf(char **buffer, size_t *buflen)
{
  FILE *fd;
  int line;
  int num_users = 0;
  struct passwd *parsed_conf;
  char *user_name;
  int char_check;

	if ((fd = fopen(CONF_FILE, "r")) == NULL ) {
		return 0;
	}

  /* Allocate some memory from the heap to store the user names. */
  char **conf_array = (char **)malloc(MAX_CONF_LINES * sizeof(char *));

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

    /*
     * Parse the config file. We can't assume that the contents of this file
     * are completely accurate, but they should give us the information we need
     * to extract accurate information from the real /etc/passwd file later.
     */
    if ((parsed_conf = fgetpwent(fd)) == NULL)
    {
      free(conf_array);
      return NULL;
    }

    /*
     * Extract just the user names from the passwd structure. We store them off
     * in the static buffer so we can access them later without them being
     * overwritten by subsequent fgetpwent() calls.
     */
    user_name = get_static(buffer, buflen, strlen(parsed_conf->pw_name) + 1);
    if (user_name == NULL) {
      free(conf_array);
      return NULL;
    }

    strcpy(user_name, parsed_conf->pw_name);
    conf_array[num_users] = user_name;
    num_users++;
  }

  /* Make sure the array is null-terminated - this will make it easier to
   * manipulate later.
   */
  conf_array[num_users] = NULL;

  fclose(fd);

  return conf_array;
}

/*
 * An environment variable (USER_LOGIN) should have been set to indicate which
 * user we should be mapping to. If it isn't, we should select the first user
 * on the list.
 */
char *
select_user(char **user_list)
{
  char *env_user_name = getenv("USER_LOGIN");
  char *user;

  syslog(LOG_AUTH|LOG_NOTICE, "libnss_ato: USER_LOGIN: %s", env_user_name);

  if (env_user_name == NULL)
    /*
     * No environment variable has been set. Just use the first entry in the
     * list. Note that we should be able to guarantee that there's at least
     * one entry in the user list by the point this function is called.
     */
    syslog(LOG_AUTH,
           "libnss_ato: No login provided, defaulting to %s",
           user_list[0]);
    return user_list[0];

  user = user_list[0];
  while (user != NULL)
  {
    if (!strcmp(env_user_name, user))
    {
      /* We've found the user we're looking for! */
      syslog(LOG_AUTH, "libnss_ato: Found user %s", user);
      return user;
    }
    syslog(LOG_AUTH, "libnss_ato: User %s didn't match", user);
    user++;
  }

  /*
   * None of the configured users match the environment variable. In this case
   * we return the first value on the list.
   */
  syslog(LOG_AUTH, "libnss_ato: Didn't find user, defaulting to %s", user);
  return user_list[0];
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
  char **conf;
  char *local_user_name;
  struct passwd *sys_passwd;

  if (!should_find_user())
  {
    syslog(LOG_AUTH|LOG_NOTICE,
           "libnss_ato: Not mapping user '%s' to default user",
           name);
    return NSS_STATUS_NOTFOUND;
  }

    /* Find the user we want to map to from the config file. */
  if ((conf = read_conf(&buffer, &buflen)) == NULL)
  {
    // If we can't read the config file, we have to return an error.
    return NSS_STATUS_NOTFOUND;
  }

  local_user_name = select_user(conf);
  syslog(LOG_AUTH|LOG_NOTICE,
         "libnss_ato: Mapping user '%s' to locally provisioned user '%s'",
         name,
         local_user_name);

  /*
   * Now we know which user to map to, we build a passwd structure that matches
   * that of the locally provisioned user, with some small tweaks.
   */
  sys_passwd = getpwnam(local_user_name);
  syslog(LOG_AUTH|LOG_NOTICE, "Pointer: %p", sys_passwd);
  if (sys_passwd != NULL)
  {
    *p = *sys_passwd;
  }

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

  /*
   * Earlier we allocated some memory to store the parsed configuration file.
   */
  free(conf);

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
