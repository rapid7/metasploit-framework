module Rex
  module Proto
    module Sms
      module Model
        class Smtp

          # @!attribute address
          #   @return [String] SMTP address
          attr_accessor :address

          # @!attribute port
          #   @return [Fixnum] SMTP port
          attr_accessor :port

          # @!attribute username
          #   @return [String] SMTP account/username
          attr_accessor :username

          # @!attribute password
          #   @return [String] SMTP password
          attr_accessor :password

          # @!attribute login_type
          #   @return [Symbol] SMTP login type (:login, :plain, and :cram_md5)
          attr_accessor :login_type

          # @!attribute from
          #   @return [String] Sender
          attr_accessor :from

          # @!attribute helo_domain
          #   @return [String] The domain to use for the HELO SMTP message
          attr_accessor :helo_domain


          # Initializes the SMTP object.
          #
          # @param [Hash] opts
          # @option opts [String] :address
          # @option opts [Fixnum] :port
          # @option opts [String] :username
          # @option opts [String] :password
          # @option opts [String] :helo_domain
          # @option opts [Symbol] :login_type
          # @option opts [String] :from
          #
          # @return [Rex::Proto::Sms::Model::Smtp]
          def initialize(opts={})
            self.address     = opts[:address]
            self.port        = opts[:port]        || 25
            self.username    = opts[:username]
            self.password    = opts[:password]
            self.helo_domain = opts[:helo_domain] || 'localhost'
            self.login_type  = opts[:login_type]  || :login
            self.from        = opts[:from]        || ''
          end

        end
      end
    end
  end
end
