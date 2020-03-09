FROM cccs/assemblyline:latest as builder
ARG version

USER root
RUN apt-get update \
  && apt-get install -yy build-essential libfuzzy-dev \
  && rm -rf /var/lib/apt/lists/*

# install pip packages, ase assemblyline so they go into our .local with the ones already there
USER assemblyline
RUN touch /tmp/before-pip
RUN pip install --user \
  assemblyline-service-client \
  assemblyline-v4-service==$version \
  awscli \
  assemblyline-client==4.0.0b5 \
  && rm -rf ~/.cache/pip

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
USER root
RUN chown root:root -R /var/lib/assemblyline/.local

# Restart a new image, this time the output one
FROM cccs/assemblyline:latest

# Get the updated local dir from builder
COPY --chown=assemblyline:assemblyline --from=builder /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Setup environment varibles
ENV PYTHONPATH /opt/al_service
ENV SERVICE_API_HOST http://localhost:5003
ENV SERVICE_API_AUTH_KEY ThisIsARandomAuthKey...ChangeMe!
ENV CONTAINER_MODE true

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Create directory for service
USER root
RUN mkdir -p /opt/al_service
RUN touch /opt/al_service/__init__.py
COPY process_handler.py /etc/

USER assemblyline
CMD python /etc/process_handler.py