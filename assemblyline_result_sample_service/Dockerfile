FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH result_sample.ResultSample

# Copy ResultSample service code
WORKDIR /opt/al_service
COPY assemblyline_result_sample_service .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline