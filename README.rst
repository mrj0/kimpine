Description
===========
This examples shows how to run Rietveld - the code review tool available
at http://codereview.appspot.com/.

Requires: Django 1.3, Python 2.6+, South_, django-debug-toolbar
Refer to requirements.txt for the whole list. Run ``pip install -r requirements.txt`` to install the
required packages.


Differences between Kimpine and Rietveld
========================================
What Kimpine has:

- Kimpine uses ``django.db.models`` rather than App Engine's db model, and so uses a query syntax
  more familiar to Django developers.
- Kimpine supports syntax highlighting in side-by-side diffs through Pygments_.
- Flexible deployment, choose your own webserver (apache+mod_wsgi, uwsgi, gunicorn, etc.)!

What Kimpine lacks:

- Notify by chat
- Integration with Google accounts
- Adjustable column widths in diffs


Using the Makefile
==================

Skip down to "Manual Setup" if you don't want to use the Makefile.

Just run::

    make all

This will fetch a recent Django and Rietveld's sources directly from their
Subversion repositories. When it's finished run::

    ./manage.py runserver

and point your browser to 127.0.0.1:8000.


Manual Setup
============

Run::

    ./manage.py syncdb

to initialize the example database. Then run the migrations (requires South_)::

    ./manage.py migrate codereview

gather all of the static files into a single ``static/`` folder::

    ./manage.py collectstatic

Finally, run the development server::

    ./manage.py runserver

will run Rietveld in development mode.

Creating and updating a code review
======================
#. Run the server (./manage.py runserver)
#. Make a change to a git repo (even this one! maybe just this file...). Leave the changes unstaged.
#. Inside that repo ``path/to/kimpine/upload.py -s 127.0.0.1:8000``. If you want to include commits in your
   codereview, just pass the same arguments you would give to ``git diff``. One common usage is
   ``upload.py -s yourCodeReviewServer.com origin/master...``
#. When prompted, provide your username/password and a subject line for your issue to be code reviewed.
#. Navigate to the site (127.0.0.1:8000) and find your issue.
#. Make comments in the diff, write a new message, etc.
#. Back in your repository, make more changes to the repo and when you're ready, update the issue: 
   ``upload.py -s 127.0.0.1:8000 -i your-issue-number`` (providing arguments for your diff, if you have more
   than just unstaged changes).
#. Navigate to your issue, check out the delta between your patchsets, make more comments, etc.
#. Rinse, repeat.


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

Go to /admin URL and login as a super user. Users may change password by logging in
and clicking the 'Change Password' link at the top of the page or visiting
/accounts/change_password .


Alternatives
============

This project is a fork of andialbrecht_'s excellent django-gae2django_ project. It takes the approach
of keeping the Rietveld codebase as intact as possible while providing a library that emulates the
App Engine APIs.


.. _South: http://south.aeracode.org/
.. _django-gae2django: http://code.google.com/p/django-gae2django/
.. _Pygments: http://pygments.org/
.. _andialbrecht: https://github.com/andialbrecht
