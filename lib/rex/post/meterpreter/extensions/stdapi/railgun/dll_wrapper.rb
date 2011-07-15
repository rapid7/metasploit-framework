module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class DLLWrapper
	attr_reader :_client, :_dll
	
	def initialize(dll, client)
		@_dll    = dll
		@_client = client
	end

	def method_missing(sym, *args)
		_dll.call_function(sym, args, _client)
	end
end
end; end; end; end; end; end
