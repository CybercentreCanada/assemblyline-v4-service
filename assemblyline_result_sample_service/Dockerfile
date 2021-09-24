ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH result_sample.ResultSample

USER root

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

USER assemblyline

# Install packages for update-server
RUN pip install gunicorn flask gitpython && rm -rf ~/.cache/pip

# Copy ResultSample service code
WORKDIR /opt/al_service
COPY assemblyline_result_sample_service .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
