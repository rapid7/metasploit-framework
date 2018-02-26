module Metasploit
  module Framework
    module LoginScanner

      # The Result class provides a standard structure in which
      # LoginScanners can return the result of a login attempt

      class Result
        include ActiveModel::Validations

        # @!attribute access_level
        #   @return [String] the access level gained
        attr_accessor :access_level
        # @!attribute credential
        #   @return [Credential] the Credential object the result is for
        attr_accessor :credential
        # @!attribute host
        #   @return [String] the addess of the target host for this result
        attr_accessor :host
        # @!attribute port
        #   @return [Integer] the port number of the service for this result
        attr_accessor :port
        # @!attribute proof
        #   @return [#to_s] the proof of the login's success or failure
        attr_accessor :proof
        # @!attribute protocol
        #   @return [String] the transport protocol used for this result (tcp/udp)
        attr_accessor :protocol
        # @!attribute service_name
        #   @return [String] the name to give the service for this result
        attr_accessor :service_name
        # @!attribute status
        #   @return [String] the status of the attempt. Should be a member of `Metasploit::Model::Login::Status::ALL`
        attr_accessor :status

        validates :status,
          inclusion: {
              in: Metasploit::Model::Login::Status::ALL
          }

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
        end

        def inspect
          "#<#{self.class} #{credential.public}:#{credential.private}@#{credential.realm} #{status} >"
        end

        def success?
          status == Metasploit::Model::Login::Status::SUCCESSFUL
        end

        # This method takes all the data inside the Result object
        # and spits out a hash compatible with #create_credential
        # and #create_credential_login.
        #
        # @return [Hash] the hash to use with #create_credential and #create_credential_login
        def to_h
          result_hash = credential.to_h
          result_hash.merge!(
              access_level: access_level,
              address: host,
              last_attempted_at: DateTime.now,
              origin_type: :service,
              port: port,
              proof: proof,
              protocol: protocol,
              service_name: service_name,
              status: status
          )
          result_hash.delete_if { |k,v| v.nil? }
        end

      end

    end
  end
end
