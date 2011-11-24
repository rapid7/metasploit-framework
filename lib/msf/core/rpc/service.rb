require "xmlrpc/server"
require 'rex/service_manager'
require "rex"


module Msf
module RPC


module MonkeyPatcher
	def initialize(*args)

		# Enable Bigint processing (required for big file sizes,etc)
		if XMLRPC::Config.const_defined?(:ENABLE_BIGINT)
			XMLRPC::Config.send(:remove_const, :ENABLE_BIGINT)
			XMLRPC::Config.const_set(:ENABLE_BIGINT, true)
		end

		# Enable nils in requests
		if XMLRPC::Config.const_defined?(:ENABLE_NIL_CREATE)
			XMLRPC::Config.send(:remove_const, :ENABLE_NIL_CREATE)
			XMLRPC::Config.const_set(:ENABLE_NIL_CREATE, true)
		end

		# Enable nils in replies
		if XMLRPC::Config.const_defined?(:ENABLE_NIL_PARSER)
			XMLRPC::Config.send(:remove_const, :ENABLE_NIL_PARSER)
			XMLRPC::Config.const_set(:ENABLE_NIL_PARSER, true)
		end

		super(*args)
	end
end

class Service < ::XMLRPC::BasicServer

	include MonkeyPatcher

	attr_accessor :service, :state, :on_input, :on_output, :on_error
	attr_accessor :dispatcher_timeout

	def initialize(srvhost, srvport, ssl=false, cert=nil, ckey=nil)

		self.dispatcher_timeout  = 0

		self.service = Rex::Socket::TcpServer.create(
			'LocalHost' => srvhost,
			'LocalPort' => srvport,
			'SSL'       => ssl
		)

		self.service.on_client_connect_proc = Proc.new { |client|
			on_client_connect(client)
		}
		self.service.on_client_data_proc = Proc.new { |client|
			begin
				Timeout.timeout(self.dispatcher_timeout) do
					on_client_data(client)
				end
			rescue ::EOFError  => e
				raise e
			rescue ::Exception => e
				wlog("XMLRPC Server Error: #{client.inspect} #{e.class} #{e} #{e.backtrace}")
				raise e
			end
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
		self.service.close
	end

	def wait
		self.service.wait
	end

	def on_client_close(c)
		self.state.delete(c)
	end

	def on_client_connect(c)
		self.state[c] = ""
		self.clean_state_table
	end

	def on_client_data(c)
		data = c.get_once(-1)
		if(not data)
			c.close
			return
		end

		if not self.state[c]
			c.close
			return
		end

		self.state[c] << data
		procxml(c)
	end

	def clean_state_table
		self.state.keys.each do |s|
			self.state.delete(s) if s.closed?
		end
	end

	def procxml(c)
		while(self.state[c].index("\x00"))
			mesg,left = self.state[c].split("\x00", 2)
			self.state[c] = left
			begin
				self.on_input.call(mesg) if self.on_input

				res = process(mesg)

				self.on_output.call(res) if self.on_output

				c.put(res+"\x00")
			rescue ::Interrupt
				raise $!
			rescue ::Exception => e
				self.on_error.call(e) if self.on_error
			end
		end
	end

end

class WebService < ::XMLRPC::BasicServer

	include MonkeyPatcher

	attr_accessor :service, :state, :srvhost, :srvport, :uri


	def initialize(port, host, uri = "/RPC2")
		self.srvhost = host
		self.srvport = port
		self.uri = uri
		self.service = nil
		super()
	end

	def start
		self.state = {}
		self.service = Rex::ServiceManager.start(
			Rex::Proto::Http::Server,
			self.srvport,
			self.srvhost,
			{}
		)

		uopts = {
			'Proc' => Proc.new { |cli, req|
				on_request_uri(cli, req)
			},
			'Path' => self.uri
		}

		self.service.add_resource(self.uri,uopts)
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
	def on_request_uri(cli, req)
		begin
			res = Rex::Proto::Http::Response.new()
			res["Content-Type"] = "text/xml"
			res.body = process(req.body)
		rescue XMLRPC::FaultException => e
			res = Rex::Proto::Http::Response.new(e.faultCode,e.faultString)
		rescue
			res = Rex::Proto::Http::Response.new(404,"An Error Occured")
		end
		cli.send_response(res)
	end

end

end
end

