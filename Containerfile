FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy requirements file first to leverage Docker caching
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and logging configuration
COPY app /app/
COPY log_config.yaml /app/

# Add a non-root user
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser

# Change ownership of the application files
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Run the application
CMD ["python", "run.py"]
