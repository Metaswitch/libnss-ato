Project Clearwater is backed by Metaswitch Networks.  We have discontinued active support for this project as of 1st December 2019.  The mailing list archive is available in GitHub.  All of the documentation and source code remains available for the community in GitHub.  Metaswitch’s Clearwater Core product, built on Project Clearwater, remains an active and successful commercial offering.  Please contact clearwater@metaswitch.com for more information. Note – this email is for commercial contacts with Metaswitch.  We are no longer offering support for Project Clearwater via this contact.

libnss-ato (Name Service Switch module All-To-One)
==========

The libnss_ato module is a set of C library extensions which allows to map every nss request for unknown user to a single predefined user.

This version of libnss-ato has been forked from [donapieppo/libnss-ato](https://github.com/donapieppo/libnss-ato), and modified slightly by Metaswitch.

Clearwater Code Management
==========================

The build infrastructure for libnss-ato is slightly different than for other Clearwater code
repositories, in order to keep a separation between the upstream code and our changes.

There are two main branches:

- master, which is our version of the libnss-ato code
- clearwater-upstream, which is master plus any Clearwater specific changes

If you're making a Clearwater specific fix, make it directly in the clearwater-upstream
branch.

If you're making any other fix, make it in master and then merge that branch into
clearwater-upstream.

Description
=========

Suppose your system has only one account (apart from root and system users) named user_test:

```console
]$ id user_test
]$ uid=1000(user_test) gid=1000 groups=1000
```

If you add libnss-ato to the chain of nss modules (in /etc/nsswitch.conf) you get something like:

```console
]$ id randomname
]$ uid=1000(user_test) gid=1000 groups=1000
```

for every query of a random username not present in /etc/passwd.

Why?
=========

This module can be used for pubblic workstations where you only need to verify username / password from a pam module (for example pam-krb5 for Active Directory users) and there is no need to give the user his own uid, gid or homedir.

Installation from source
=========
From source just make and make install.

The only configuration file is `/etc/libnss-ato.conf` which consists of one line in the passwd format. For example:

```console
test_user:x:1000:1000:Test User,:/home/test:/bin/bash
```

Only the first line of the file `/etc/libnss-ato.conf` is parsed.

Here an example of the system file `/etc/nsswitch.conf` to make use of libnss-ato:

```console
passwd:         files ato
group:          files
shadow:         files ato
```

Installation from Debian packages
=========
To build the Debian packages, run the following:
```console
make deb
```
This should create the correct `.deb` in the parent directory.

This package can then be installed as with any other package:
```console
sudo dpkg -i <package_name>
```
You will then need to modify the config files, as above.

Installation from CentOS packages
=========
To build the CentOS packages, run the following:
```console
make rpm
```
This should create the correct `.rpm` in the parent directory.

This package can then be installed as with any other package:
```console
sudo yum install <package_name>
```
You will then need to modify the config files, as above.
