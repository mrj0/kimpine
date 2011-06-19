Description
===========
This examples shows how to run Rietveld - the code review tool available
at http://codereview.appspot.com/.

Before you are able to run this example you need to obtain a recent version
of Rietveld. There are two ways to do this. Either set it up manually or
use the Makefile in this directory.


Using the Makefile
==================

Skip down to "Manual Setup" if you don't want to use the Makefile.

Just run::

    make all

This will fetch a recent Django and Rietveld's sources directly from their
Subversion repositories. When it's finished run::

    ./manage.py runserver 127.0.0.1:8000

and point your browser to that location.


Manual Setup
============

Run::

    ./manage.py syncdb

to initialize the example database

::

./manage.py runserver 127.0.0.1:8000

will run Rietveld in development mode.


Production Deployment
=====================

The preferred method to deploy Django applications is to use WSGI supporting
web server. You may copy codereview.wsgi.example and edit it to change
/var/rietveld path to point to your installation.

There is one important thing to remember. Django serves media (static) files
only in development mode. For running Rietveld in a production environment,
you need to setup your web-server to serve the /static/ alias directly.

http://docs.djangoproject.com/en/dev/howto/deployment/modpython/#serving-media-files

There is the example configuration for running Rietveld with Apache2+mod_wsgi
Feel free to copy it from apache.conf.example. You may need to change
'codereview' user name in WSGI directives and adjust paths to match your
installation.

When running in a production environment, keep in Django's CSRF
protection is disabled in this example!


Adding Users
============

Go to /admin URL and login as a super user. Users may change password by
going to /admin/password_change URL.
