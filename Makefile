default:
	@echo "Run 'make all' to prepare the code review app (create db, migrate, collect static files)"

all: requirements dev.db migrate static
	@echo "Run './manage.py runserver' to run Rietveld."

clean: clean_db clean_pyc clean_static

clean_db:
	rm -f dev.db

clean_pyc:
	find . -name "*.pyc" | xargs rm

clean_static:
	rm -rf static/

requirements:
	pip install -r requirements.txt

dev.db:
	./manage.py syncdb

migrate:
	./manage.py migrate codereview

static:
	./manage.py collectstatic
