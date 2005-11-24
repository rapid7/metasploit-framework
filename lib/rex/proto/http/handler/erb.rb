require 'erb'

module Rex
module Proto
module Http

###
#
# This class implements a handler for ERB (.rhtml) template files.  This is
# based off the webrick handler.
#
###
class Handler::Erb < Handler

	#
	# ERB handlers required a relative resource so that the full path name can
	# be computed.
	#
	def self.relative_resource_required?
		true
	end

	#
	# Initializes the ERB handler
	#
	def initialize(server, root_path, opts = {})
		super(server)

		self.root_path = root_path
		self.opts = opts

		self.opts['MimeType'] = "text/html" unless self.opts['MimeType']
	end

	#
	# Called when a request arrives.
	#
	def on_request(cli, req)
		resource = req.relative_resource

		# Make sure directory traversals aren't happening
		if (resource =~ /\.\./)
			wlog("Erb::on_request: Dangerous request performed: #{resource}",
				LogSource)
			return
		end

		begin
			resp = Response.new

			# Calculate the actual file path on disk.
			file_path = root_path + resource
		
			puts "file path is #{file_path}"

			# Serialize the contents of the file
			data = ::IO.readlines(file_path).join

			# Evaluate the data and set the output as the response body.
			resp.body = evaluate(ERB.new(data), cli, req, resp)

			# Set the content-type to text/html by default.
			resp['Content-Type'] = opts['MimeType']
		rescue
			elog("Erb::on_request: #{$!}\n\n#{$@.join("\n")}", LogSource)

			puts "exception: #{$!} #{$@.join("\n")}"

			resp = Response::E404.new
		end

		# Send the response to the 
		if (cli and resp)
			cli.send_response(resp)
		end

		resp
	end

	#
	# Evaulates the ERB context in a specific binding context.
	#
	def evaluate(erb, cli, request, response)
		# If the thing that created this handler wanted us to use a callback
		# instead of the default behavior, then let's do that.
		if (opts['Callback'])
			opts['Callback'].call(erb, cli, request, response)
		else
			Module.new.module_eval {
				query_string = request.qstring
				meta_vars = request.meta_vars
				erb.result(binding)
			}
		end
	end

protected

	attr_accessor :root_path, :opts # :nodoc:

end

end
end
end
