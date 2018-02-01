FROM ruby:2.4.3-alpine3.7
LABEL maintainer="Rapid7"

ARG BUNDLER_ARGS="--jobs=8 --without development test coverage"
ENV APP_HOME /usr/src/metasploit-framework/
ENV MSF_USER msf
ENV NMAP_PRIVILEGED=""
ENV BUNDLE_IGNORE_MESSAGES="true"
WORKDIR $APP_HOME

COPY Gemfile* metasploit-framework.gemspec Rakefile $APP_HOME
COPY lib/metasploit/framework/version.rb $APP_HOME/lib/metasploit/framework/version.rb
COPY lib/metasploit/framework/rails_version_constraint.rb $APP_HOME/lib/metasploit/framework/rails_version_constraint.rb
COPY lib/msf/util/helper.rb $APP_HOME/lib/msf/util/helper.rb

RUN apk update && \
    apk add \
      sqlite-libs \
      nmap \
      nmap-scripts \
      nmap-nselibs \
      postgresql-libs \
      python \
      python3 \
      ncurses \
      libcap \
    && apk add --virtual .ruby-builddeps \
      autoconf \
      bison \
      build-base \
      ruby-dev \
      libressl-dev \
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
RUN /usr/sbin/setcap cap_net_raw,cap_net_bind_service=+eip $(which nmap)

USER $MSF_USER

ADD ./ $APP_HOME

CMD ["./msfconsole", "-r", "docker/msfconsole.rc"]
