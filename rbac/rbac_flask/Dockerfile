FROM python:3.7.1

LABEL Author="Gines Garcia Aviles"
LABEL E-mail="gigarcia@it.uc3m.es"
LABEL version="0.1b"

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev

WORKDIR /

COPY ./requirements.txt /requirements.txt
RUN pip3 install -r requirements.txt

RUN mkdir rbac_flask

ADD ./app /rbac_flask/app
ADD ./rbac_app.py /rbac_flask
ADD ./keycloak.json /rbac_flask/app/keycloak

WORKDIR /rbac_flask

CMD [ "python3", "rbac_app.py" ]
