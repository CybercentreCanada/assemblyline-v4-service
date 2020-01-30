FROM cccs/assemblyline:latest

ARG version

# Setup environment varibles
ENV PYTHONPATH /opt/al_service
ENV SERVICE_API_HOST http://localhost:5003
ENV SERVICE_API_AUTH_KEY ThisIsARandomAuthKey...ChangeMe!
ENV CONTAINER_MODE true

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Switch to root to install dependencies
USER root

# Pipy packages requirements
RUN pip install \
  assemblyline \
  assemblyline-service-client \
  assemblyline-v4-service==$version \
  awscli \
  assemblyline-client==4.0.0b4

# Create directory for service
RUN mkdir -p /opt/al_service
RUN touch /opt/al_service/__init__.py

COPY process_handler.py /etc/
CMD python /etc/process_handler.py