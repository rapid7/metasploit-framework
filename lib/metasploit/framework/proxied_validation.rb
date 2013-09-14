module Metasploit
  module Framework
    module ProxiedValidation
      def errors
        validation_proxy.errors
      end

      def invalid?(context=nil)
        !valid?(context)
      end

      def valid?(context=nil)
        validation_proxy.valid?(context)
      end

      def validation_proxy
        @validation_proxy ||= validation_proxy_class.new(target: self)
      end
    end
  end
end