require "xmlrpc/server"
require "rex"

module Msf
module RPC
class Service < ::XMLRPC::BasicServer

	attr_accessor :service, :state
	
	def initialize(srvhost, srvport, ssl=false, cert=nil, ckey=nil)
		self.service = Rex::Socket::TcpServer.create(
			'LocalHost' => srvhost,
			'LocalPort' => srvport,
			'SSL'       => ssl
		)

		self.service.on_client_connect_proc = Proc.new { |client|
			on_client_connect(client)
		}
		self.service.on_client_data_proc = Proc.new { |client|
			on_client_data(client)
		}
		self.service.on_client_close_proc = Proc.new { |client|
			on_client_close(client)
		}

		self.state = {}
		super()
	end
	
	def start
		self.state = {}
		self.service.start
	end
	
	def stop
		self.state = {}
		self.service.stop
	end
	
	def wait
		self.service.wait
	end
	
	def on_client_close(c)
		self.state.delete(c)
	end
	
	def on_client_connect(c)
		self.state[c] = ""
	end
	
	def on_client_data(c)
		data = c.get_once(-1)
		self.state[c] << data if data
		
		procxml(c)
	end

	def procxml(c)
		while(self.state[c].index("\x00"))
			mesg,left = self.state[c].split("\x00", 2)
			self.state[c] = left
			begin
				res = process(mesg)
			rescue ::Exception => e
				$stderr.puts "ERROR: #{e.class} #{e}"
			end
			c.put(res+"\x00")
		end
	end

end
end
end
