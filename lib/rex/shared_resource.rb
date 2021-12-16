# -*- coding: binary -*-

# A tag interface used to indicate that the object in question should not be
# replicated as part of the replicant process in modules.
#
# Note that atomic access isn't granted to the caller, and additional mutex/semaphores
# may be required to behave as expected in a threaded context.
module Rex::SharedResource
end
