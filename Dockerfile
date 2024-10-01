FROM python:3.9

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt /app/

RUN pip3 install -r requirements.txt

RUN apt-get update && \
    apt-get install -y pandoc texlive texlive-latex-extra texlive-xetex && \
    apt-get clean

COPY . /app/
COPY fonts/ /usr/local/share/fonts/

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]