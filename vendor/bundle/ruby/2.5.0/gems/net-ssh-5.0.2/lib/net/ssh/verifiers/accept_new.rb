require 'net/ssh/errors'
require 'net/ssh/known_hosts'
require 'net/ssh/verifiers/always'

module Net
  module SSH
    module Verifiers

      # Does a strict host verification, looking the server up in the known
      # host files to see if a key has already been seen for this server. If this
      # server does not appear in any host file, this will silently add the
      # server. If the server does appear at least once, but the key given does
      # not match any known for the server, an exception will be raised (HostKeyMismatch).
      # Otherwise, this returns true.
      class AcceptNew < Always
        def verify(arguments)
          begin
            super
          rescue HostKeyUnknown => err
            err.remember_host!
            return true
          end
        end
      end

    end
  end
end
