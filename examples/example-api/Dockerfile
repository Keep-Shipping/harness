# example-api: a stdlib-only service, so the build needs nothing but Python.
FROM python:3.12-alpine

WORKDIR /srv
COPY app.py .

EXPOSE 8080
CMD ["python", "app.py"]