FROM python:3.10.9-bullseye

WORKDIR /opt/app/src
COPY . /opt/app/src

RUN pip install .
RUN /opt/app/src/bin/nuclei -ud /opt/app/src/nuclei-templates