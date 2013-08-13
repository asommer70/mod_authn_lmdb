mod_authn_lmdb
==============

Apache authentication module using lmdb.  mod_authn_lmdb checks a lmdb database 
for a key matching a username with a password encrypted using an Apache encryption 
method.

mod_authn_lmdb can be used as a sort of credentials cache when stacked in front of 
other authentication modules like mod_authnz_external.


# Requirements

* lmdb: http://symas.com/mdb/
* libapr1-dev
* libaprutil1-dev
* apache2-threaded-dev
* openssl

On Ubuntu:
'''
sudo apt-get install libapr1-dev libaprutil1-dev apache2-threaded-dev
'''

OpenSSL should be installed by default, but if not:
'''
sudo apt-get install openssl
'''

Install lmdb:
'''
git clone https://git.gitorious.org/mdb/mdb.git
cd mdb/libraries/liblmdb/
make
sudo make install
'''

# Installation

Install mod_authn_lmdb:
'''
apxs2 -c mod_authn_lmdb.c -llmdb
sudo apxs2 -i -a mod_authn_lmdb.la
sudo service apache2 restart
'''

# Configuration

In your Apache configuration, inside a <location> or <directory> directive add:
'''
AuthLmdbDir "/var/lib/lmdb"
'''

Where _/var/lib/lmdb_ is a directory containing your lmdb database.

Don't forget to create the directory:
'''
sudo mkdir /var/lib/lmdb
'''

Setup HTTP Basic authentication for the directory/location and set the _AuthBasicProfiver_ to _lmdb_:
'''
AuthType Basic
AuthName "Authentication For The Authenticated"
AuthBasicProvider lmdb
Require valid-user
'''

Restart Apache:
'''
sudo service apache2 restart
'''

Installation and configuration steps should be similar on other Linux distributions, and mod_authn_lmdb might even work on Windows.... maybe.

# add_entry.c

This is a sample program to add username key with a SHA1 password encrypted using the apr_sha1_base64 function.

## Compiling add_entry.c

To compile the utility use something like:
'''
gcc -Wall -o add_entry add_entry.c /usr/local/lib/liblmdb.so /usr/lib/libaprutil-1.so.0
'''

Add entries to your lmdb with:
'''
./add_entry /var/lib/lmdb someuser somepass
'''

Obviously this utility could be made better, but who has the time?
