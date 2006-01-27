require 'uri'
require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# HTTP request class.
#
###
class Request < Packet

	##
	#
	# Some individual request types.
	#
	##
	
	#
	# HTTP GET request class wrapper.
	#
	class Get < Request
		def initialize(uri = '/', proto = DefaultProtocol)
			super('GET', uri, proto)
		end
	end

	#
	# HTTP POST request class wrapper.
	#
	class Post < Request
		def initialize(uri = '/', proto = DefaultProtocol)
			super('POST', uri, proto)
		end
	end

	#
	# HTTP PUT request class wrapper.
	#
	class Put < Request
		def initialize(uri = '/', proto = DefaultProtocol)
			super('PUT', uri, proto)
		end
	end

	#
	# Initializes an instance of an HTTP request with the supplied method, URI,
	# and protocol.
	#
	def initialize(method = 'GET', uri = '/', proto = DefaultProtocol)
		super()

		self.method    = method
		self.raw_uri   = uri
		self.uri_parts = {}
		self.proto     = proto || DefaultProtocol

		update_uri_parts
	end

	#
	# Updates the command parts for this specific packet type.
	#
	def update_cmd_parts(str)
		if (md = str.match(/^(.+?)\s+(.+?)\s+HTTP\/(.+?)\r?\n?$/))
			self.method  = md[1]
			self.raw_uri = URI.decode(md[2])
			self.proto   = md[3]

			update_uri_parts
		else
			raise RuntimeError, "Invalid request command string", caller
		end
	end

	#
	# Split the URI into the resource being requested and its query string.
	#
	def update_uri_parts
		# If it has a query string, get the parts.
		if ((self.raw_uri) and (md = self.raw_uri.match(/(.+?)\?(.*)$/)))
			self.uri_parts['QueryString'] = parse_cgi_qstring(md[2])
			self.uri_parts['Resource']    = md[1]
		# Otherwise, just assume that the URI is equal to the resource being
		# requested.
		else
			self.uri_parts['QueryString'] = {}
			self.uri_parts['Resource']    = self.raw_uri
		end

		# Set the relative resource to the actual resource.
		self.relative_resource = resource
	end

	# Puts a URI back together based on the URI parts
	def uri
		uri = self.uri_parts['Resource'] || '/'
		
		# /././././
		if self.junk_self_referring_directories
			uri.gsub!(/\//) {
				'/.' * (rand(3) + 1) + '/'
			}
		end

		# /RAND/../RAND../
		if self.junk_directories 
			uri.gsub!(/\//) {
				dirs = ''
				rand(5)+5.times {
					dirs += '/' + Rex::Text.rand_text_alpha(rand(5) + 1) + '/..'
				}
				dirs + '/'
			}
		end

		# ////
		#
		# NOTE: this must be done after junk directories, since junk_directories would cancel this out
		if self.junk_slashes
			uri.gsub!(/\//) {
				'/' * (rand(3) + 1)
			}
			uri.gsub!(/^[\/]+/, '/') # only one beginning slash!
		end

		if self.method != 'POST' 
			params=[]
			self.uri_parts['QueryString'].each_pair { |param, value|
				# inject a random number of params in between each param
				if self.junk_params
					rand(10)+5.times {
						params.push(Rex::Text.rand_text_alpha(rand(16) + 5) + '=' + Rex::Text.rand_text_alpha(rand(10) + 1))
					}
				end
				if !value.nil?
					params.push(self.escape(param) + '=' + self.escape(value))
				else 
					params.push(self.escape(param))
				end
			}

			# inject some junk params at the end of the param list, just to be sure :P
			if self.junk_params
				rand(10)+5.times {
					params.push(Rex::Text.rand_text_alpha(rand(32) + 5) + '=' + Rex::Text.rand_text_alpha(rand(64) + 5))
				}
			end

			if params.size > 0
				uri += '?' + params.join('&')
			end
		end
		uri
	end

	# Updates the underlying URI structure
	def uri=(uri)
		self.raw_uri = uri
		update_uri_parts
	end

	# Returns a URI escaped version of the provided string, by providing an additional argument, all characters are escaped
	def escape(str, all = nil)
		if all
			return str.gsub(/./) { |s| Rex::Text.to_hex(s, '%') }
		else 
			return str.gsub(/[^a-zA-Z1-9]/) { |s| Rex::Text.to_hex(s, '%') }
		end
	end


	#
	# Returns the command string derived from the three values.
	#
	def cmd_string
		"#{self.method} #{self.uri} HTTP/#{self.proto}\r\n"
	end

	#
	# Returns the resource that is being requested.
	#
	def resource
		self.uri_parts['Resource']
	end

	#
	# Changes the resource URI.  This is used when making a request relative to
	# a given mount point.
	#
	def resource=(rsrc)
		self.uri_parts['Resource'] = rsrc
	end

	#
	# If there were CGI parameters in the URI, this will hold a hash of each
	# variable to value.  If there is more than one value for a given variable,
	# and array of each value is returned.
	#
	def qstring
		self.uri_parts['QueryString']
	end

	#
	# Returns a hash of variables that contain information about the request,
	# such as the remote host information.
	#
	# TODO
	#
	def meta_vars
	end

	#
	# The method being used for the request (e.g. GET).
	#
	attr_accessor :method
	#
	# The raw URI being requested, before any mucking gets to it
	#
	attr_accessor :raw_uri

	#
	# The split up parts of the URI.
	#
	attr_accessor :uri_parts
	#
	# The protocol to be sent with the request.
	#
	attr_accessor :proto
	#
	# The resource path relative to the root of a server mount point.
	#
	attr_accessor :relative_resource

	# add junk directories
	attr_accessor :junk_directories
	
	# add junk slashes 
	attr_accessor :junk_slashes

	# add junk self referring directories (aka  /././././
	attr_accessor :junk_self_referring_directories

	# add junk params
	attr_accessor :junk_params

protected

	#
	# Parses a CGI query string into the var/val combinations.
	#
	def parse_cgi_qstring(str)
		qstring = {}

		# Delimit on each variable
		str.split(/&/).each { |vv|
			var = vv
			val = ''
			
			if (md = vv.match(/(.+?)=(.*)/))
				var = md[1]
				val = md[2]
			end

			# Add the item to the hash with logic to convert values to an array
			# if so desired.
			if (qstring.include?(var))
				if (qstring[var].kind_of?(Array))
					qstring[var] << val
				else
					curr = self.qstring[var]
					qstring[var] = [ curr, val ]
				end
			else
				qstring[var] = val
			end
		}

		return qstring
	end

end

end
end
end
