# Deliberately insecure sample for CodeSift tests. Never build for production.
FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl
# REAL: piping a remote script into a shell
RUN curl -sSL https://example.com/install.sh | bash
# REAL: ADD from a remote URL
ADD https://example.com/app.tar.gz /opt/app.tar.gz

COPY . /app
WORKDIR /app
# REAL: no USER instruction - runs as root
CMD ["python3", "app.py"]
