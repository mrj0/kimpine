RIETVELDREV=671

default:
	@echo "Run 'make all' to fetch required sources to run this example."

all: django gae2django dev.db
	@echo "Run './manage.py runserver 127.0.0.1:8000' to run Rietveld."

clean: clean_local clean_external

clean_external: clean_rietveld clean_django

clean_django:
	unlink django

clean_local:
	unlink gae2django
	rm -f dev.db

gae2django:
	ln -s ../django-gae2django/gae2django .

dev.db:
	./manage.py syncdb

django:
	ln -s ../django .
