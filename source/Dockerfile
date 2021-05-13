FROM python:3.9.3

WORKDIR /usr/src/app

COPY ./requirements.txt .

RUN pip install -r requirements.txt

COPY . .

ENV SECRET_KEY="default_secret_key"

ENV FLASK_APP run.py

ENV FLASK_ENV development

ENV MONGO_URI mongodb://db:27017/packetenizer

EXPOSE 5000

CMD ["gunicorn", "-w", "3", "-b", "0.0.0.0:5000", "run:app"]