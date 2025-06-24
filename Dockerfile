FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy dependencies first (for better caching)
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your app
COPY . .

# Expose the port Flask runs on
EXPOSE 8000

# Run your app with waitress
CMD ["waitress-serve", "--host=0.0.0.0", "--port=8000", "app:app"]
