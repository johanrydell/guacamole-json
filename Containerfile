FROM python:3.12-slim

# Install FastAPI and Uvicorn
COPY requirements.txt /app/
WORKDIR /app
RUN pip install -r requirements.txt

# Copy app code into container
COPY app/. /app/

# Run Uvicorn server
#CMD ["uvicorn", "app.app:app", "--host", "0.0.0.0", "--port", "8000"]
CMD ["python", "app.py"]