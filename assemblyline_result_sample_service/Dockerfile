FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH result_sample.ResultSample

# Switch to assemblyline user
USER assemblyline

# Copy ResultSample service code
WORKDIR /opt/al_service
COPY assemblyline_result_sample_service .