FROM python:3.7-alpine

# Copy python script under PATH
COPY inou.py /usr/local/bin

# Set entrypoint for container
ENTRYPOINT ["python3", "/usr/local/bin/inou.py"]
