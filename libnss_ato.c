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
#include <stdio.h>

/*
 * Match to the list of process names for which this module should return a
 * result.
 * They are processes which call nss_ato on login, and user-run OS command line
 * programs.
 */
const char *VALID_PROC_NAMES[] = {"sshd",
                                  "login",
                                  "w"};

/*
 * Array length macro
 * The size of the whole array divided by the size of the 1st element is the
 * length of the array
 */
#define arraylen(array) ((sizeof(array))/(sizeof(array[0])))

#define FALSE 0
#define TRUE 1

/* for security reasons */
#define MIN_UID_NUMBER   500
#define MIN_GID_NUMBER   500
#define CONF_FILE "/etc/libnss-ato.conf"

/*
 * the configuration /etc/libnss-ato.conf is just one line
 * with the local user data as in /etc/passwd. For example:
 * dona:x:1001:1001:P D ,,,:/home/dona:/bin/bash
 * Extra lines are comments (not processed).
 */



struct passwd *
read_conf() 
{
	FILE *fd;
	struct passwd *conf;

	if ((fd = fopen(CONF_FILE, "r")) == NULL ) {
		return NULL;
	}
	conf = fgetpwent(fd);

	if ( conf->pw_uid < MIN_UID_NUMBER )
		conf->pw_uid = MIN_UID_NUMBER;

	if ( conf->pw_gid < MIN_GID_NUMBER )
		conf->pw_gid = MIN_GID_NUMBER;

	fclose(fd);
	return conf;
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
      // DEBUG_LOG("libnss_ato: Process name matched '%s'", VALID_PROC_NAMES[i]);
      return TRUE;
    }
  }

  // Process name didn't match any that we want.
  return FALSE;
}


enum nss_status
_nss_ato_getpwnam_r( const char *name, 
	   	     struct passwd *p, 
	             char *buffer, 
	             size_t buflen, 
	             int *errnop)
{
	struct passwd *conf;

  if (!should_find_user())
  {
    // DEBUG_LOG("libnss_ato: We shouldn't return this user");
    return NSS_STATUS_NOTFOUND;
  }
  
	if ((conf = read_conf()) == NULL) {
		return NSS_STATUS_NOTFOUND;
	}

	*p = *conf;

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
          // DEBUG_LOG("libnss_ato: We shouldn't return this user");
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

        return NSS_STATUS_SUCCESS;
}
