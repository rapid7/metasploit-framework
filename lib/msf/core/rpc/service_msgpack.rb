
# We reuse the XMLRPC::Exception class for fault handling
require 'xmlrpc/server'

require 'msgpack'

require 'rex'
require 'rex/service_manager'


module Msf
module RPC

class MessagePackService

	attr_accessor :service, :state, :srvhost, :srvport, :uri, :options
	attr_accessor :handlers, :default_handler, :method_blacklist
	attr_accessor :dispatcher_timeout
	
	def initialize(host, port, options={})
		self.dispatcher_timeout = 7200
		self.handlers = {}
		self.options  = {
			:ssl  => false,
			:cert => nil,
			:key  => nil,
			:uri  => "/uri"
		}.merge(options)
		
		self.srvhost = host
		self.srvport = port
		self.uri     = self.options[:uri]
		self.method_blacklist = (Object.methods + Object.new.methods).uniq.map{|x| x.to_s }
		self.state 
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
	
	def on_request_uri(cli, req)
		begin
			res = Rex::Proto::Http::Response.new()
			res["Content-Type"] = "binary/message-pack"
			res.body = process(req.body).to_msgpack
		rescue XMLRPC::FaultException => e
			res = Rex::Proto::Http::Response.new(500, "Error: #{e.class} #{e} #{e.backtrace}")
		end
		cli.send_response(res)
	end
	
	def add_handler(group, handler)
		self.handlers[group] = handler
	end

	
	def process(data)
		begin
			msg = MessagePack.unpack(data)
			
			if not (msg and msg.kind_of?(::Array) and msg.length > 0)
				raise ArgumentError, "Invalid Message Format"
			end
			
			group, funct = msg.shift.split(".", 2)
			
			if not self.handlers[group]
				raise ArgumentError, "Unknown API Call"
			end

			if not ( self.handlers[group] and self.handlers[group].respond_to?(funct) )
				raise ArgumentError, "Unknown API Call"
			end
			
			if self.method_blacklist.include?(funct)
				raise ArgumentError, "Prohibited Method Call"
			end
			
			::Timeout.timeout(self.dispatcher_timeout) { self.handlers[group].send(funct, *msg) }
		
		rescue ::Exception => e
			process_exception(e)
		end
	end
	
	def process_exception(e)
		r = {
			:result          => 'error',
			:error_class     => e.class.to_s,
			:error_string    => e.to_s,
			:error_backtrace => e.backtrace
		}

		if e.respond_to?(:faultString)
			r[:fault_string] = e.faultString
		end
				
		if e.respond_to?(:faultCode)
			r[:fault_code] = e.faultCode
		end
				
		r
	end

end

end
end

