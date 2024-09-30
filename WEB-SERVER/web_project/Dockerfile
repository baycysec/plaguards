# Gunakan image Python official sebagai base image
FROM python:3.9

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set direktori kerja di dalam container
WORKDIR /app

# Salin file requirements.txt ke dalam container
COPY requirements.txt /app/
COPY fonts/ /usr/local/share/fonts/

# Install dependencies menggunakan pip
RUN pip3 install -r requirements.txt

# Update the package list and install pandoc
RUN apt-get update && \
    apt-get install -y pandoc texlive texlive-latex-extra texlive-xetex && \
    apt-get clean

# Salin semua file dari direktori project Django ke dalam container
COPY . /app/

# Expose port 8000 untuk diakses dari luar container
EXPOSE 8000

# Jalankan perintah untuk menjalankan server Django saat container dijalankan
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
