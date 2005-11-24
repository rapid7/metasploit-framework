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
	def initialize(server, procedure)
		super(server)

		self.procedure = procedure
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

end

end
end
end
