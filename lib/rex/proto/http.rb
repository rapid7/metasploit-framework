# These are required by all uses of Rex::Proto::Http
require 'rex/proto/http/packet'
require 'rex/proto/http/request'
require 'rex/proto/http/response'

# These are specific to use case
module Rex
module Proto
module Http

	autoload :Client, 'rex/proto/http/client'

	autoload :Server,  'rex/proto/http/server'
	autoload :Handler, 'rex/proto/http/handler'

end
end
end
