ARG branch=latest
ARG base=cccs/assemblyline-v4-service-base
FROM $base:$branch

ENV SERVICE_PATH extra_feature.ExtraFeature

USER assemblyline

# Copy ExtraFeature service code
WORKDIR /opt/al_service
COPY assemblyline_extra_feature_service .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
