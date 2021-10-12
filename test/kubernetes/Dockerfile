FROM alpine:3.14.2

WORKDIR /kubernetes

RUN apk add --no-cache curl make perl openssl openssh-client
RUN curl --output helm.tar.gz https://get.helm.sh/helm-v3.7.1-linux-amd64.tar.gz && \
    (echo "6cd6cad4b97e10c33c978ff3ac97bb42b68f79766f1d2284cfd62ec04cd177f4  helm.tar.gz" | sha256sum -c -) && \
    tar -zxvf helm.tar.gz linux-amd64/helm --strip-components 1 && \
    mv helm /usr/local/bin && \
    rm helm.tar.gz

RUN curl -LO "https://dl.k8s.io/release/v1.22.2/bin/linux/amd64/kubectl" && \
    chmod +x ./kubectl && \
    mv kubectl /usr/local/bin
