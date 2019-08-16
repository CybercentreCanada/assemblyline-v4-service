FROM cccs/assemblyline:latest

ARG version

# Setup environment varibles
ENV PYTHONPATH /opt/al:/opt/al/al_services
ENV SERVICE_API_HOST http://localhost:5003
ENV SERVICE_API_AUTH_KEY ThisIsARandomAuthKey...ChangeMe!

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Switch to root to install dependencies
USER root

# Pipy packages requirements
RUN pip3 install \
  assemblyline \
  assemblyline-service-client \
  assemblyline-v4-service==$version

# Create directory for service
RUN mkdir -p /opt/al/al_services
RUN touch /opt/al/al_services/__init__.py

COPY process_handler.py /etc/
CMD python3 /etc/process_handler.py