module Msf
module Recon

require 'msf/core/recon/attribute/container'

###
#
# EventContext
# ------------
#
# This mixin provides an abstract interface to the ``context'' parameter that
# is passed around to the recon event handlers.  Instances of this are meant
# to contain data that is specific to the event being reported and is meant to
# be conveyed in a form that allows other recon modules to only pay attention
# to the things that it cares about.  For instance, one recon module may wish
# to allow other recon modules to re-use the TCP connection it established to
# a host for future probing.  This connection instance would be conveyed
# through the event context in a known attribute.
#
###
class EventContext
	include Attribute::Container
end

end
end
