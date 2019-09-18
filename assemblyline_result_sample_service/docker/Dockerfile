FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH alsvc_resultsample.result_sample.ResultSample

# Switch to assemblyline user
USER assemblyline

# Copy ResultSample service code
WORKDIR /opt/al/al_services/alsvc_resultsample
COPY assemblyline_result_sample_service .