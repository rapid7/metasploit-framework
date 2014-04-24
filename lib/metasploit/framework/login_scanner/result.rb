module Metasploit
  module Framework
    module LoginScanner

      # The Result class provides a standard structure in which
      # LoginScanners can return the result of a login attempt

      class Result

        # @!attribute [r] private
        #   @return [String] the private(e.g. password) component
        attr_reader :private
        # @!attribute [r] proof
        #   @return [String,nil] the proof that the lgoin was successful
        attr_reader :proof
        # @!attribute [r] public
        #   @return [String] the public(e.g. username) component
        attr_reader :public
        # @!attribute [r] realm
        #   @return [String] the realm(e.g. domain name) component
        attr_reader :realm
        # @!attribute [r] status
        #   @return [Symbol] the status of the attempt (e.g. success, failed, etc)
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
