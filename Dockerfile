FROM python:3.12-slim

WORKDIR /srv

# Install deps as a layer — only rebuilds when requirements.txt changes
COPY app/requirements.txt /srv/app/requirements.txt
RUN pip install --no-cache-dir -r /srv/app/requirements.txt

# App code copied separately so dep layer is cached
COPY app/ /srv/app/

EXPOSE 8099
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099", "--log-level", "info"]
