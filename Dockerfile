FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# dashboard
EXPOSE 8888
# the honeypot ports you map in docker-compose
CMD ["python", "honeypot_main.py"]
