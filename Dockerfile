FROM circleci/node:8.11.2-stretch
MAINTAINER "Manojvv" "manojv@ilimi.in"
USER root
COPY src /opt/content/
WORKDIR /opt/content/
RUN npm install --unsafe-perm

FROM node:8.11-slim
LABEL maintainer="Manojvv <manojv@ilimi.in>"
RUN useradd -m sunbird
COPY --from=0 --chown=sunbird /opt/content /home/sunbird/mw/content
WORKDIR /home/sunbird/mw/content/
CMD ["node", "app.js", "&"]
