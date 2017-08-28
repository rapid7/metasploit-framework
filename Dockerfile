FROM ruby:2.4.1-alpine
MAINTAINER Rapid7

ARG BUNDLER_ARGS="--jobs=8 --without development test coverage"
ENV APP_HOME /usr/src/metasploit-framework/
ENV MSF_USER msf
ENV NMAP_PRIVILEGED=""
WORKDIR $APP_HOME

COPY Gemfile* m* Rakefile $APP_HOME
COPY lib $APP_HOME/lib

RUN apk update && \
    apk add \
      sqlite-libs \
      nmap \
      nmap-scripts \
      nmap-nselibs \
      postgresql-libs \
      ncurses \
      libcap \
    && apk add --virtual .ruby-builddeps \
      autoconf \
      bison \
      build-base \
      ruby-dev \
      openssl-dev \
      readline-dev \
      sqlite-dev \
      postgresql-dev \
      libpcap-dev \
      libxml2-dev \
      libxslt-dev \
      yaml-dev \
      zlib-dev \
      ncurses-dev \
      git \
    && echo "gem: --no-ri --no-rdoc" > /etc/gemrc \
    && gem update --system \
    && gem install bundler \
    && bundle install --system $BUNDLER_ARGS \
    && apk del .ruby-builddeps \
    && rm -rf /var/cache/apk/*

RUN adduser -g msfconsole -D $MSF_USER

RUN /usr/sbin/setcap cap_net_raw,cap_net_bind_service=+eip $(which ruby)
RUN /usr/sbin/setcap cap_net_raw,cap_net_bind_service=+eip /usr/bin/nmap

USER $MSF_USER

ADD ./ $APP_HOME

CMD ["./msfconsole", "-r", "docker/msfconsole.rc"]
