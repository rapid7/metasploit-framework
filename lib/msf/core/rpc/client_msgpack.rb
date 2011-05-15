require "xmlrpc/client"
require "msgpack"

require "rex"
require "rex/proto/http"

module Msf
module RPC

# Loosely based on the XMLRPC::ClientS class
# Reimplemented for Metasploit

class MessagePackClient

	attr_accessor :sock, :token, :info


	def initialize(info={})
		self.info = {
			:host => '127.0.0.1',
			:port => 55552,
			:uri  => '/api',
			:ssl  => false,
			:ssl_version => 'SSLv3'
		}.merge(info)
		
		self.token = self.info[:token]
	end


	def login(user,pass)
		res = self.call("auth.login", user, pass)
		if(not (res and res['result'] == "success"))
			raise RuntimeError, "authentication failed"
		end
		self.token = res['token']
		true
	end

	# Prepend the authentication token as the first parameter
	# of every call except auth.login. Requires the
	def call(meth, *args)
		if(meth != "auth.login")
			if(not self.token)
				raise RuntimeError, "client not authenticated"
			end
			args.unshift(self.token)
		end
		
		args.unshift(meth)
		
		cli = Rex::Proto::Http::Client.new(info[:host], info[:port], info[:ssl], info[:ssl_version])
		cli.set_config(:vhost => info[:host])
		req = cli.request_cgi(
			'method' => 'POST',
			'uri'    => self.info[:uri],
			'ctype'  => 'binary/message-pack',
			'data'   => args.to_msgpack
		)

		res = cli.send_recv(req)
		
		if res and res.code == 200
			return MessagePack.unpack(res.body)
		else
			raise RuntimeError, res.inspect
		end
	end

	def close
		self.sock.close rescue nil
		self.sock = nil
	end

end
end
end

