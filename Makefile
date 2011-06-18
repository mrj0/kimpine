default:
	@echo "Run 'make all' to fetch required sources to run this example."

all: dev.db
	@echo "Run './manage.py runserver 127.0.0.1:8000' to run Rietveld."

clean: clean_db clean_pyc

clean_db:
	rm -f dev.db

clean_pyc:
	find . -name "*.pyc" | xargs rm

dev.db:
	./manage.py syncdb
