FROM ruby:2.6.2-alpine3.9 AS builder
LABEL maintainer="Rapid7"

ARG BUNDLER_ARGS="--jobs=8 --without development test coverage"
ENV APP_HOME=/usr/src/metasploit-framework
ENV BUNDLE_IGNORE_MESSAGES="true"
WORKDIR $APP_HOME

COPY Gemfile* metasploit-framework.gemspec Rakefile $APP_HOME/
COPY lib/metasploit/framework/version.rb $APP_HOME/lib/metasploit/framework/version.rb
COPY lib/metasploit/framework/rails_version_constraint.rb $APP_HOME/lib/metasploit/framework/rails_version_constraint.rb
COPY lib/msf/util/helper.rb $APP_HOME/lib/msf/util/helper.rb

RUN apk add --no-cache \
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
    && bundle install --clean --no-cache --system $BUNDLER_ARGS \
    # temp fix for https://github.com/bundler/bundler/issues/6680
    && rm -rf /usr/local/bundle/cache \
    # needed so non root users can read content of the bundle
    && chmod -R a+r /usr/local/bundle


FROM ruby:2.6.2-alpine3.9
LABEL maintainer="Rapid7"

ENV APP_HOME=/usr/src/metasploit-framework
ENV NMAP_PRIVILEGED=""
ENV METASPLOIT_GROUP=metasploit

# used for the copy command
RUN addgroup -S $METASPLOIT_GROUP

RUN apk add --no-cache bash sqlite-libs nmap nmap-scripts nmap-nselibs postgresql-libs python python3 ncurses libcap su-exec

RUN /usr/sbin/setcap cap_net_raw,cap_net_bind_service=+eip $(which ruby)
RUN /usr/sbin/setcap cap_net_raw,cap_net_bind_service=+eip $(which nmap)

COPY --chown=root:metasploit --from=builder /usr/local/bundle /usr/local/bundle
COPY --chown=root:metasploit . $APP_HOME/
RUN cp -f $APP_HOME/docker/database.yml $APP_HOME/config/database.yml

WORKDIR $APP_HOME

# we need this entrypoint to dynamically create a user
# matching the hosts UID and GID so we can mount something
# from the users home directory. If the IDs don't match
# it results in access denied errors.
ENTRYPOINT ["docker/entrypoint.sh"]

CMD ["./msfconsole", "-r", "docker/msfconsole.rc", "-y", "$APP_HOME/config/database.yml"]
