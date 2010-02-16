require 'net/ssh/errors'

module Net; module SSH; module Proxy

  # A general exception class for all Proxy errors.
  class Error < Net::SSH::Exception; end

  # Used for reporting proxy connection errors.
  class ConnectError < Error; end

  # Used when the server doesn't recognize the user's credentials.
  class UnauthorizedError < Error; end

end; end; end
