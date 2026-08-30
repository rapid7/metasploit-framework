FROM tomcat:9.0

# The manager app lives in webapps.dist in modern Tomcat images — move it into place
RUN cp -r /usr/local/tomcat/webapps.dist/. /usr/local/tomcat/webapps/

# Add a manager-gui and manager-script user for testing
RUN sed -i 's|</tomcat-users>|<role rolename="manager-gui"/><role rolename="manager-script"/><user username="tomcat" password="tomcat" roles="manager-gui,manager-script"/></tomcat-users>|' \
    /usr/local/tomcat/conf/tomcat-users.xml

# Remove the localhost-only RemoteAddrValve so the manager is reachable from outside the container
RUN sed -i '/<Valve/d' /usr/local/tomcat/webapps/manager/META-INF/context.xml
