module Msf
  module Handler
    module Reverse
      autoload :Comm, 'msf/core/handler/reverse/comm'
      autoload :SSL, 'msf/core/handler/reverse/ssl'
    end
  end
end
