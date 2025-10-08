FROM python:3.11-slim
WORKDIR /srv
COPY app /srv/app
RUN pip install --no-cache-dir -r /srv/app/requirements.txt
ENV APP_SECRET_KEY=change-me
EXPOSE 8000
WORKDIR /srv/app
CMD ["python", "app.py"]
