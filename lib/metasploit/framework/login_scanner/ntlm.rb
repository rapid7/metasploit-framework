require 'metasploit/framework/login_scanner'

module Metasploit
  module Framework
    module LoginScanner

      # This Concern provides the basic accessors and validations
      # for protocols that require the use of NTLM for Authentication.
      module NTLM
        extend ActiveSupport::Concern
        include ActiveModel::Validations

        included do
          # @!attribute send_lm
          #   @return [Boolean] Whether or not to always send the LANMAN response(except if using NTLM2 Session)
          attr_accessor :send_lm

          # @!attribute send_ntlm
          #   @return [Boolean] Whether or not to use NTLM responses
          attr_accessor :send_ntlm

          # @!attribute send_spn
          #   @return [Boolean] Whether or not to support SPN for newer Windows OSes
          attr_accessor :send_spn

          # @!attribute send_lm
          #   @return [Boolean] Whether or not to force the use of NTLM2 session
          attr_accessor :use_ntlm2_session

          # @!attribute send_lm
          #   @return [Boolean] Whether or not to force the use of NTLMv2 instead of NTLM2 Session
          attr_accessor :use_ntlmv2

          validates :send_lm,
                    inclusion: { in: [true, false] }

          validates :send_ntlm,
                    inclusion: { in: [true, false] }

          validates :send_spn,
                    inclusion: { in: [true, false] }

          validates :use_ntlm2_session,
                    inclusion: { in: [true, false] }

          validates :use_ntlmv2,
                    inclusion: { in: [true, false] }
        end

      end

    end
  end
end
