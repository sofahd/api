FROM alpine:3.17
# Define build-time variables
ARG TOKEN
ARG LOG_API
ARG EXT_PORT

# Set the build-time variable as an environment variable
ENV LOG_API=${LOG_API}
ENV EXT_PORT=${EXT_PORT}

# Copy files
COPY ./src /home/api/
COPY ./data/files /home/api/files

# Update apt repository and install dependencies
RUN apk --no-cache -U add \
    python3 \
    py3-pip \
    git \
    curl \
    python3-dev && \
    pip3 install setuptools \ 
    flask \
    wheel \
    requests \
    pyuwsgi \
    exrex && \
    mkdir /home/api/answerset && \
    pip3 install git+https://$TOKEN:x-oauth-basic@github.com/sofahd/sofahutils.git

WORKDIR /home/api

CMD uwsgi --http 0.0.0.0:50005 --http-keepalive=1 --master -p 1 -w api:app
