default:
	@echo "Run 'make all' to prepare the code review app (create db, migrate, collect static files)"

all: dev.db migrate static
	@echo "Run './manage.py runserver' to run Rietveld."

clean: clean_db clean_pyc clean_static

clean_db:
	rm -f dev.db

clean_pyc:
	find . -name "*.pyc" | xargs rm

clean_static:
	rm -rf static/

dev.db:
	./manage.py syncdb

migrate:
	./manage.py migrate codereview

static:
	./manage.py collectstatic
