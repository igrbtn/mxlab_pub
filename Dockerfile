FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/

# Expose ports (SMTP and Web)
EXPOSE 2525 5000

# Run the application
CMD ["python", "app.py"]
