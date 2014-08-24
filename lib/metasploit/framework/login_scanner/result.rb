module Metasploit
  module Framework
    module LoginScanner

      # The Result class provides a standard structure in which
      # LoginScanners can return the result of a login attempt

      class Result
        include ActiveModel::Validations

        # @!attribute [r] access_level
        #   @return [String] the access level gained
        attr_reader :access_level
        # @!attribute [r] credential
        #   @return [Credential] the Credential object the result is for
        attr_reader :credential
        # @!attribute [r] proof
        #   @return [String,nil] the proof that the lgoin was successful
        attr_reader :proof
        # @!attribute [r] status
        #   @return [String] the status of the attempt. Should be a member of `Metasploit::Model::Login::Status::ALL`
        attr_reader :status

        validates :status,
          inclusion: {
              in: Metasploit::Model::Login::Status::ALL
          }

        # @param [Hash] opts The options hash for the initializer
        # @option opts [String] :private The private credential component
        # @option opts [String] :proof The proof that the login was successful
        # @option opts [String] :public The public credential component
        # @option opts [String] :realm The realm credential component
        # @option opts [String] :status The status code returned
        def initialize(opts= {})
          @access_level = opts.fetch(:access_level, nil)
          @credential   = opts.fetch(:credential)
          @proof        = opts.fetch(:proof, nil)
          @status       = opts.fetch(:status)
        end

        def success?
          status == Metasploit::Model::Login::Status::SUCCESSFUL
        end

        def inspect
          "#<#{self.class} #{credential.public}:#{credential.private}@#{credential.realm} #{status} >"
        end

      end

    end
  end
end
