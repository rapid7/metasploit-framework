# A docker container to generate empty ysoserial payloads and metadata to allow for
# dynamically creating payloads within related projects, such as Metasploit
#
#   Created by:  Aaron Soto, Rapid7 Metasploit Team, 2018-DEC-11
#
# To run:
#   docker build -t ysoserial-payloads . && docker run -i ysoserial-payloads > ysoserial_offsets.json
#
# Note: There will be ruby gem errors.  It's fine.
#       We attempt to use the ysoserial-modified fork, then fail back to the original ysoserial project.
#       You will see warnings, but we're doing our best.  :-)

FROM ubuntu

RUN apt update && apt -y upgrade
# Dependencies: wget (to download ysoserial)
#               openjdk-8-jre-headless (to execute ysoserial)
#               make, gcc (to install the 'json' ruby gem)
RUN apt install -y wget openjdk-8-jre-headless ruby-dev make gcc

# Download the latest ysoserial-modified
RUN wget -q https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O ysoserial-original.jar
RUN wget -q https://github.com/pimps/ysoserial-modified/raw/master/target/ysoserial-modified.jar

# Install gems: diff-lcs (to diff the ysoserial output)
#               json (to print the scripts results in JSON)
#               pry (to debug issues)
RUN gem install --silent diff-lcs json pry

COPY find_ysoserial_offsets.rb /

CMD ruby /find_ysoserial_offsets.rb
