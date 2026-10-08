FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (better layer caching)
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy the whole project (backend + frontend)
COPY . .

EXPOSE 8000

# Use $PORT when provided by the host (Render, Hugging Face Spaces, etc.)
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
