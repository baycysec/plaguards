FROM python:3.10

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV VT_API_KEY="your_api_key_goes_here"

COPY ./others/eisvogel.latex /usr/share/pandoc/data/templates/eisvogel.latex

WORKDIR /app

COPY requirements.txt /app/

RUN pip3 install -r requirements.txt

RUN apt-get update && \
    apt-get install -y pandoc texlive texlive-latex-extra texlive-xetex && \
    apt-get install -y texlive-fonts-extra && \
    apt-get install -y apt-utils

COPY . /app/
COPY fonts/ /usr/local/share/fonts/

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
