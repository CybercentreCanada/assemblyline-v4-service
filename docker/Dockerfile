ARG branch=latest
ARG base=cccs/assemblyline
FROM $base:$branch as builder
ARG version
ARG branch

USER root
RUN apt-get update \
  && apt-get install -yy build-essential libfuzzy-dev \
  && rm -rf /var/lib/apt/lists/*

# install pip packages, as assemblyline so they go into our .local with the ones already there
USER assemblyline
RUN touch /tmp/before-pip
COPY setup.py dist* dist/
RUN pip install --no-cache-dir -f dist --user \
  assemblyline-core==$version \
  assemblyline-service-client==$version \
  assemblyline-v4-service==$version[updater] \
  assemblyline-client \
  && rm -rf ~/.cache/pip

# If this is a latest rather than stable build, try to push for unstable packages of assemblyline dependencies
RUN if [ "${branch}" = "latest" ]; then pip install --user --upgrade --pre assemblyline-client; fi

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
USER root
RUN chown root:root -R /var/lib/assemblyline/.local

# Restart a new image, this time the output one
ARG base=cccs/assemblyline
FROM $base:$branch

# Get the updated local dir from builder
COPY --chown=assemblyline:assemblyline --from=builder /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Setup environment varibles
ENV PYTHONPATH /opt/al_service
ENV SERVICE_API_HOST http://al_service_server:5003
ENV SERVICE_API_KEY ThisIsARandomAuthKey...ChangeMe!
ENV CONTAINER_MODE true

USER root
# Install git binary for gitpython pip package
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Create directory for service
RUN mkdir -p /opt/al_service
RUN touch /opt/al_service/__init__.py
COPY docker/process_handler.py /etc/

# Create directory for service updates
RUN mkdir /updates
RUN chown -R assemblyline:assemblyline /updates

USER assemblyline
CMD ["python", "/etc/process_handler.py"]
