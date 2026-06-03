FROM tomcat:9.0

# Download Axis2 1.6.2 WAR (last version verified by the Metasploit module)
RUN apt-get update -qq && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*
RUN wget -q https://archive.apache.org/dist/axis/axis2/java/core/1.6.2/axis2-1.6.2-war.zip \
    -O /tmp/axis2.zip && \
    apt-get update -qq && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/* && \
    unzip -q /tmp/axis2.zip -d /tmp/axis2 && \
    cp /tmp/axis2/axis2.war /usr/local/tomcat/webapps/ && \
    rm -rf /tmp/axis2 /tmp/axis2.zip

# Move the bundled Tomcat apps into place (they live in webapps.dist in modern images)
RUN cp -r /usr/local/tomcat/webapps.dist/. /usr/local/tomcat/webapps/

# Restore the Server header so fingerprint checks pass (Tomcat 9 suppresses it by default)
RUN sed -i 's|<Connector port="8080"|<Connector port="8080" server="Apache-Coyote/1.1"|' \
    /usr/local/tomcat/conf/server.xml
