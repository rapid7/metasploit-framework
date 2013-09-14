# -*- coding: binary -*-
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
    rescue Errno::EPIPE
      elog("Proc::on_request: Client closed connection prematurely", LogSource)
    rescue
      elog("Proc::on_request: #{$!.class}: #{$!}\n\n#{$@.join("\n")}", LogSource)
      if self.server and self.server.context
        exploit = self.server.context['MsfExploit']
        if exploit
          exploit.print_error("Exception handling request: #{$!}")
        end
      end
    end
  end

protected

  attr_accessor :procedure # :nodoc:
  attr_accessor :virt_dir  # :nodoc:

end

end
end
end
