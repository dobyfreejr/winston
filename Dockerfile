# Use the official Python image for Raspberry Pi
FROM arm32v7/python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Expose the port your app runs on
EXPOSE 6200
# Set the command to run your application
CMD ["python", "app.py"]  # Replace 'app.py' with your main Flask file
