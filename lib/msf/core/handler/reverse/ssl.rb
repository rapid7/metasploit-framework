module Msf
  module Handler
    module Reverse
      module SSL
        #
        # Adds the certificate option.
        #
        def initialize(info = {})
          super
          register_advanced_options(
            [
              OptPath.new('HandlerSSLCert', [false, "Path to a SSL certificate in unified PEM format"])
            ], Msf::Handler::Reverse::SSL)

        end
      end
    end
  end
end
