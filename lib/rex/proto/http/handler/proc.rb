require 'erb'

module Rex
module Proto
module Http

###
#
# This class is used to wrapper the calling of a procedure when a request
# arrives.
#
###
class Handler::Proc < Handler

	#
	# Initializes the proc handler with the supplied procedure
	#
	def initialize(server, procedure, virt_dir = false)
		super(server)

		self.procedure = procedure
		self.virt_dir  = virt_dir || false
	end

	#
	# Returns true if the procedure is representing a virtual directory.
	#
	def relative_resource_required?
		virt_dir	
	end

	#
	# Called when a request arrives.
	#
	def on_request(cli, req)
		begin
			procedure.call(cli, req)
		rescue
			elog("Proc::on_request: #{$!}\n\n#{$@.join("\n")}", LogSource)
		end
	end

protected

	attr_accessor :procedure # :nodoc:
	attr_accessor :virt_dir  # :nodoc:

end

end
end
end