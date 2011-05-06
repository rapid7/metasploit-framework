##
# $Id$
#
# This file maps Proto items for autoload
##

module Rex
module Proto

	autoload :Http,   'rex/proto/http'
	autoload :SMB,    'rex/proto/smb'
	autoload :NTLM,   'rex/proto/ntlm'
	autoload :DCERPC, 'rex/proto/dcerpc'
	autoload :DRDA,   'rex/proto/drda'

	autoload :SunRPC, 'rex/proto/sunrpc'
	autoload :DHCP,   'rex/proto/dhcp'
	autoload :TFTP,   'rex/proto/tftp'
	autoload :RFB,    'rex/proto/rfb'

	attr_accessor :alias

end
end
