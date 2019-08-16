FROM cccs/assemblyline_dev:latest

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/alv4:/opt/alv4/alv4_service_client:/opt/alv4/alv4_service:/opt/al:/opt/al/al_services
ENV SERVICE_API_HOST http://localhost:5003
ENV SERVICE_API_AUTH_KEY ThisIsARandomAuthKey...ChangeMe!

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Switch to root to install dependencies
USER root

COPY alv4_service/docker/v4_service_base_dev/requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

COPY alv4_service_client/requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

# Cleanup
RUN rm /tmp/requirements.txt*

# Create directory for service
RUN mkdir -p /opt/al/al_services
RUN touch /opt/al/al_services/__init__.py

COPY alv4_service/docker/v4_service_base_dev/process_handler.py /etc/
CMD python3 /etc/process_handler.py