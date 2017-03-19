FROM ruby:2.3-alpine
MAINTAINER Rapid7

ARG BUNDLER_ARGS="--system --jobs=8"
ENV APP_HOME /usr/src/metasploit-framework/
WORKDIR $APP_HOME

COPY Gemfile* m* Rakefile $APP_HOME
COPY lib $APP_HOME/lib

RUN apk update && \
	apk add \
  	ruby-bigdecimal \
  	ruby-bundler \
  	ruby-io-console \
    autoconf \
  	bison \
  	subversion \
  	git \
  	sqlite \
  	nmap \
  	libxslt \
  	postgresql \
    ncurses \
  && apk add --virtual .ruby-builddeps \
    build-base \
    ruby-dev \
    libffi-dev\
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
    bison \
    autoconf \
  && echo "gem: --no-ri --no-rdoc" > /etc/gemrc \
  && bundle install $BUNDLER_ARGS \
  && apk del .ruby-builddeps \
  && rm -rf /var/cache/apk/*

ADD ./ $APP_HOME
CMD ["./msfconsole", "-r", "docker/msfconsole.rc"]
