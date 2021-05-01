FROM python:3.9.3

WORKDIR /usr/src/app

COPY ./requirements.txt .

RUN pip install -r requirements.txt

COPY . .

ENV SECRET_KEY="default_secret_key"

EXPOSE 8000

CMD ["gunicorn", "run:app", "-b", "0.0.0.0:8000"]