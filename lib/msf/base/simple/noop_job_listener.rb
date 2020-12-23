require 'singleton'

module Msf
  module Simple
    class NoopJobListener

      include Singleton

      def waiting(id); end

      def start(id); end

      def completed(id, result, mod); end

      def failed(id, error, mod); end
    end
  end
end
