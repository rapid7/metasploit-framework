module Metasploit
  module Framework
    module LoginScanner

      class Result

        attr_reader :private
        attr_reader :proof
        attr_reader :public
        attr_reader :realm
        attr_reader :status

        # @param [Hash] opts The options hash for the initializer
        # @option opts [String] :private The private credential component
        # @option opts [String] :proof The proof that the login was successful
        # @option opts [String] :public The public credential component
        # @option opts [String] :realm The realm credential component
        # @option opts [Symbol] :status The status code returned
        def initialize(opts= {})
          @private = opts.fetch(:private)
          @proof   = opts.fetch(:proof)
          @public  = opts.fetch(:public)
          @realm   = opts.fetch(:realm)
          @status  = opts.fetch(:status)
        end

        def success?
          status == :success
        end

      end

    end
  end
end
