require 'rex/proto/smb'
require 'metasploit/framework'
require 'metasploit/framework/tcp/client'
require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/login_scanner/rex_socket'
require 'metasploit/framework/login_scanner/ntlm'

module Metasploit
  module Framework
    module LoginScanner

      # This is the LoginScanner class for dealing with the Server Messaging
      # Block protocol.
      class SMB
        include Metasploit::Framework::Tcp::Client
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LoginScanner::RexSocket
        include Metasploit::Framework::LoginScanner::NTLM

        CAN_GET_SESSION      = true
        LIKELY_PORTS         = [ 139, 445 ]
        LIKELY_SERVICE_NAMES = [ "smb" ]
        PRIVATE_TYPES        = [ :password, :ntlm_hash ]
        REALM_TYPE           = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN

        module StatusCodes
          CORRECT_CREDENTIAL_STATUS_CODES = [
            "STATUS_ACCOUNT_DISABLED",
            "STATUS_ACCOUNT_EXPIRED",
            "STATUS_ACCOUNT_RESTRICTION",
            "STATUS_INVALID_LOGON_HOURS",
            "STATUS_INVALID_WORKSTATION",
            "STATUS_LOGON_TYPE_NOT_GRANTED",
            "STATUS_PASSWORD_EXPIRED",
            "STATUS_PASSWORD_MUST_CHANGE",
          ].freeze.map(&:freeze)
        end


        # @!attribute simple
        #   @return [Rex::Proto::SMB::SimpleClient]
        attr_accessor :simple

        attr_accessor :smb_chunk_size
        attr_accessor :smb_name
        attr_accessor :smb_native_lm
        attr_accessor :smb_native_os
        attr_accessor :smb_obscure_trans_pipe_level
        attr_accessor :smb_pad_data_level
        attr_accessor :smb_pad_file_level
        attr_accessor :smb_pipe_evasion

        # UNUSED
        #attr_accessor :smb_pipe_read_max_size
        #attr_accessor :smb_pipe_read_min_size
        #attr_accessor :smb_pipe_write_max_size
        #attr_accessor :smb_pipe_write_min_size
        attr_accessor :smb_verify_signature

        attr_accessor :smb_direct

        validates :smb_chunk_size,
                  numericality:
                  {
                    only_integer: true,
                    greater_than_or_equal_to: 0
                  }

        validates :smb_obscure_trans_pipe_level,
                  inclusion:
                  {
                    in: Rex::Proto::SMB::Evasions::EVASION_NONE .. Rex::Proto::SMB::Evasions::EVASION_MAX
                  }

        validates :smb_pad_data_level,
                  inclusion:
                  {
                    in: Rex::Proto::SMB::Evasions::EVASION_NONE .. Rex::Proto::SMB::Evasions::EVASION_MAX
                  }

        validates :smb_pad_file_level,
                  inclusion:
                  {
                    in: Rex::Proto::SMB::Evasions::EVASION_NONE .. Rex::Proto::SMB::Evasions::EVASION_MAX
                  }

        validates :smb_pipe_evasion,
                  inclusion: { in: [true, false, nil] },
                  allow_nil: true

        # UNUSED
        #validates :smb_pipe_read_max_size, numericality: { only_integer: true }
        #validates :smb_pipe_read_min_size, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
        #validates :smb_pipe_write_max_size, numericality: { only_integer: true }
        #validates :smb_pipe_write_min_size, numericality: { only_integer: true, greater_than_or_equal_to: 0 }

        validates :smb_verify_signature,
                  inclusion: { in: [true, false, nil] },
                  allow_nil: true


        # (see Base#attempt_login)
        def attempt_login(credential)

          # Disable direct SMB when SMBDirect has not been set and the
          # destination port is configured as 139
          if self.smb_direct.nil?
            self.smb_direct = case self.port
                              when 139 then false
                              when 445 then true
                              end
          end

          begin
            connect
          rescue ::Rex::ConnectionError => e
            return Result.new(credential:credential, status: :connection_error, proof: e)
          end
          proof = nil

          begin
            # TODO: OMG
            ok = simple.login(
              smb_name,
              credential.public,
              credential.private,
              credential.realm || "",
              smb_verify_signature,
              use_ntlmv2,
              use_ntlm2_session,
              send_lm,
              use_lmkey,
              send_ntlm,
              smb_native_os,
              smb_native_lm,
              {
                use_spn: send_spn,
                name: host
              }
            )

            simple.connect("\\\\#{smb_name}\\IPC$")
            status = ok ? :success : :failed
          rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
            status = case e.get_error(e.error_code)
                     when *StatusCodes::CORRECT_CREDENTIAL_STATUS_CODES
                       :correct
                     when 'STATUS_LOGON_FAILURE', 'STATUS_ACCESS_DENIED'
                       :failed
                     else
                       puts e.backtrace.join
                       :failed
                     end

            proof = e
          rescue ::Rex::Proto::SMB::Exceptions::Error => e
            status = :failed
            proof = e
          rescue ::Rex::ConnectionError
            status = :connection_error
          end

          Result.new(credential: credential, status: status, proof: proof)
        end

        def connect
          disconnect
          self.sock = super

          c = Rex::Proto::SMB::SimpleClient.new(sock, smb_direct)

          c.client.evasion_opts['pad_data'] = smb_pad_data_level
          c.client.evasion_opts['pad_file'] = smb_pad_file_level
          c.client.evasion_opts['obscure_trans_pipe'] = smb_obscure_trans_pipe_level

          self.simple = c
          c
        end

        def set_sane_defaults
          self.connection_timeout           = 10 if self.connection_timeout.nil?
          self.max_send_size                = 0 if self.max_send_size.nil?
          self.send_delay                   = 0 if self.send_delay.nil?
          self.send_lm                      = true if self.send_lm.nil?
          self.send_ntlm                    = true if self.send_ntlm.nil?
          self.send_spn                     = true if self.send_spn.nil?
          self.smb_chunk_size               = 0 if self.smb_chunk_size.nil?
          self.smb_name                     = "*SMBSERVER" if self.smb_name.nil?
          self.smb_native_lm                = "Windows 2000 5.0" if self.smb_native_os.nil?
          self.smb_native_os                = "Windows 2000 2195" if self.smb_native_os.nil?
          self.smb_obscure_trans_pipe_level = 0 if self.smb_obscure_trans_pipe_level.nil?
          self.smb_pad_data_level           = 0 if self.smb_pad_data_level.nil?
          self.smb_pad_file_level           = 0 if self.smb_pad_file_level.nil?
          self.smb_pipe_evasion             = false if self.smb_pipe_evasion.nil?
          #self.smb_pipe_read_max_size       = 1024 if self.smb_pipe_read_max_size.nil?
          #self.smb_pipe_read_min_size       = 0 if self.smb_pipe_read_min_size.nil?
          #self.smb_pipe_write_max_size      = 1024 if self.smb_pipe_write_max_size.nil?
          #self.smb_pipe_write_min_size      = 0 if self.smb_pipe_write_min_size.nil?
          self.smb_verify_signature         = false if self.smb_verify_signature.nil?

          self.use_lmkey              = true if self.use_lmkey.nil?
          self.use_ntlm2_session            = true if self.use_ntlm2_session.nil?
          self.use_ntlmv2                   = true if self.use_ntlmv2.nil?

          self.smb_name = self.host if self.smb_name.nil?

        end
      end
    end
  end
end

