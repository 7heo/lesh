Let's Encrypt SHell script
==========================

I wrote this script because I was unsatisifed with every existing method. The
approach in this script isn't very elegant and it could reuse a lot more than
it does (Let's Encrypt has a concept of Account that one can reuse, this tool
re-creates an account for every call; etc.)

This script is loosely based on the [Let's Encrypt Simple Client at
Calomel.org](https://calomel.org/lets_encrypt_client.html).

This script has been tested on Debian 7.11 and OpenBSD 6.1.

Requirements
------------

This script assumes that an httpd is present on your server, and serving HTTP
requests for your domain. This script makes no attempt at configuring the httpd
for you.

How to use
----------

This script is configured using environment variables, and is used as follows:

    BASEDIR=/path/to/certs/ WEBDIR=/path/to/www/ DOMAINS=domain.tld CA=https://acme-v01.api.letsencrypt.org le.sh && reload-httpd

Where:
- `BASEDIR` is the base directory where the script will execute, and place the
	certificates.
- `WEBDIR` is the directory (relatively to `BASEDIR`, if not set absolutely)
	that is served by the httpd under `http://$domain/.well-known/acme-challenge`
	and writable by the user executing the script.
- `DOMAINS` is a space separated list of domains that the certificate has to be
	generated for. The first domain will be used for the openssl CN and as the
	name to access the HTTP server.
- `CA` is the URL of the let's encrypt endpoint to use.

Additional notes
----------------

This repository contains a template nginx configuration for using with this
script.
