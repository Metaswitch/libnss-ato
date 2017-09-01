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
 * It's useful to be able to pass around a mapping of user name to UID.
 */
struct user_id_map
{
  char *user_name;
  uid_t uid;
};

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
struct user_id_map *read_conf(char **buffer, size_t *buflen)
{
  FILE *fd;
  int line;
  int char_check;
  int num_users = 0;

  struct passwd *parsed_conf;
  char *user_name;

	if ((fd = fopen(CONF_FILE, "r")) == NULL ) {
		return 0;
	}

  /* Allocate some memory from the heap to store the user names. */
  struct user_id_map *conf_array =
     (struct user_id_map *)malloc(MAX_CONF_LINES * sizeof(struct user_id_map));

  for (line = 0; line < MAX_CONF_LINES; line++)
  {
    char_check = getc(fd);
    if ((char)char_check == '#') {
      /* Lines that start with a # are comments. Ignore them. */
      char junk[1000];
      fgets(junk, sizeof(junk), fd);
      continue;
    } else if (char_check == EOF) {
      /* There are no more lines to parse! */
      break;
    } else {
      /*
       * Because the first character isn't a #, we want to parse this line.
       * Push the character back onto the stream so we can read it normally.
       */
      ungetc(char_check, fd);
    }

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
     * Extract the user name and UID from the passwd structure. We store the
     * usernames in the static buffer so we can access them later without them
     * being overwritten by subsequent fgetpwent() calls.
     */
    user_name = get_static(buffer, buflen, strlen(parsed_conf->pw_name) + 1);
    if (user_name == NULL) {
      free(conf_array);
      return NULL;
    }

    strcpy(user_name, parsed_conf->pw_name);

    /* For security, don't allow this for users below MIN_UID_NUMBER. */
    if ( parsed_conf->pw_uid < MIN_UID_NUMBER )
      parsed_conf->pw_uid = MIN_UID_NUMBER;

    conf_array[num_users] = (struct user_id_map){user_name,
                                                 parsed_conf->pw_uid};
    num_users++;
  }

  /*
   * Make sure the array is null-terminated - this will make it easier to
   * manipulate later.
   */
  conf_array[num_users] = (struct user_id_map){NULL, 0};

  fclose(fd);

  return conf_array;
}

/*
 * An environment variable (USER_LOGIN) should have been set to indicate which
 * user we should be mapping to. If it isn't, we should select the first user
 * on the list.
 */
uid_t select_uid(struct user_id_map *user_list)
{
  char *env_user_name = getenv("USER_LOGIN");
  int user_idx;
  struct user_id_map user;

  syslog(LOG_AUTH|LOG_NOTICE, "libnss_ato: USER_LOGIN: %s", env_user_name);

  if (env_user_name == NULL)
  {
    /*
     * No environment variable has been set. This indicates that no RADIUS
     * authentication has taken place yet, so we don't know which user to map
     * to. Return 0 to indicate we can't decide.
     */
    syslog(LOG_AUTH, "libnss_ato: Unknown which user to map to");
    return 0;
  }

  user = user_list[0];
  for (user_idx=0; user_list[user_idx].user_name != NULL; user_idx++)
  {
    user = user_list[user_idx];
    if (!strcmp(env_user_name, user.user_name))
    {
      /* We've found the user we're looking for! */
      syslog(LOG_AUTH, "libnss_ato: Found user %s", user.user_name);
      return user.uid;
    }
    syslog(LOG_AUTH, "libnss_ato: User %s didn't match", user.user_name);
  }

  /*
   * None of the configured users match the environment variable. In this case
   * we return the first value on the list.
   */
  syslog(LOG_AUTH,
         "libnss_ato: Didn't find user, defaulting to %s",
         user.user_name);
  return user_list[0].uid;
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
_nss_ato_getpwnam_r(const char *name,
                    struct passwd *p,
                    char *buffer,
                    size_t buflen,
                    int *errnop)
{
  struct user_id_map* conf;
  uid_t local_uid;
  struct passwd *user_passwd;

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

  /* Find the passwd structure matching the chosen UID. */
  local_uid = select_uid(conf);
  if (!local_uid)
  {
    syslog(LOG_AUTH|LOG_NOTICE, "libnss-ato: No user to map to");
    return NSS_STATUS_TRYAGAIN;
  }

  user_passwd = getpwuid(local_uid);

  /*
   * There isn't a user that matches the specified UID.
   */
  if (!user_passwd)
  {
    syslog(LOG_AUTH, "libnss_ato: UID %d didn't match", local_uid);
    return NSS_STATUS_NOTFOUND;
  }

  syslog(LOG_AUTH|LOG_NOTICE,
         "libnss_ato: Mapping user '%s' to locally provisioned user '%s'",
         name,
         user_passwd->pw_name);
  *p = *user_passwd;

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
