FROM ubuntu:18.04

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/alv4:/opt/alv4/alv4_service_client:/opt/alv4/alv4_service:/opt/al:/opt/al/al_services
ENV SERVICE_API_HOST http://localhost:5003

RUN apt-get update && apt-get install -y \
  git \
  libfuzzy-dev \
  python3.7 \
  python3.7-dev \
  python3-pip \
  supervisor

# Pipy packages requirements
RUN pip3 install assemblyline assemblyline-service-client assemblyline-v4-service==$version


# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/al/al_services
RUN touch /opt/al/al_services/__init__.py

# Supervisor
RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]