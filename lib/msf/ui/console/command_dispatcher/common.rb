# -*- coding: binary -*-

require 'rexml/document'
require 'rex/parser/nmap_xml'
require 'msf/core/db_export'

module Msf
module Ui
module Console
module CommandDispatcher

  # These are functions that are used in two or more command dispatchers.

module Common

  # Parse +arg+ into a {Rex::Socket::RangeWalker} and append the result into +host_ranges+
  #
  # @note This modifies +host_ranges+ in place
  #
  # @param arg [String] The thing to turn into a RangeWalker
  # @param host_ranges [Array] The array of ranges to append
  # @param required [Boolean] Whether an empty +arg+ should be an error
  # @return [Boolean] true if parsing was successful or false otherwise
  def arg_host_range(arg, host_ranges, required=false)
    if (!arg and required)
      print_error("Missing required host argument")
      return false
    end
    begin
      rw = Rex::Socket::RangeWalker.new(arg)
    rescue
      print_error("Invalid host parameter, #{arg}.")
      return false
    end

    if rw.valid?
      host_ranges << rw
    else
      print_error("Invalid host parameter, #{arg}.")
      return false
    end
    return true
  end

  #
  # Parse +arg+ into an array of ports and append the result into +port_ranges+
  #
  # Returns true if parsing was successful or nil otherwise.
  #
  # NOTE: This modifies +port_ranges+
  #
  def arg_port_range(arg, port_ranges, required=false)
    if (!arg and required)
      print_error("Argument required for -p")
      return
    end
    begin
      port_ranges << Rex::Socket.portspec_to_portlist(arg)
    rescue
      print_error("Invalid port parameter, #{arg}.")
      return
    end
    return true
  end

  #
  # Set RHOSTS in the +active_module+'s (or global if none) datastore from an array of addresses
  #
  # This stores all the addresses to a temporary file and utilizes the
  # <pre>file:/tmp/filename</pre> syntax to confer the addrs.  +rhosts+
  # should be an Array.  NOTE: the temporary file is *not* deleted
  # automatically.
  #
  def set_rhosts_from_addrs(rhosts)
    if rhosts.empty?
      print_status("The list is empty, cowardly refusing to set RHOSTS")
      return
    end
    if active_module
      mydatastore = active_module.datastore
    else
      # if there is no module in use set the list to the global variable
      mydatastore = self.framework.datastore
    end

    if rhosts.length > 5
      # Lots of hosts makes 'show options' wrap which is difficult to
      # read, store to a temp file
      rhosts_file = Rex::Quickfile.new("msf-db-rhosts-")
      mydatastore['RHOSTS'] = 'file:'+rhosts_file.path
      # create the output file and assign it to the RHOSTS variable
      rhosts_file.write(rhosts.join("\n")+"\n")
      rhosts_file.close
    else
      # For short lists, just set it directly
      mydatastore['RHOSTS'] = rhosts.join(" ")
    end

    print_line "RHOSTS => #{mydatastore['RHOSTS']}"
    print_line
  end

  def show_options(mod) # :nodoc:
    mod_opt = Serializer::ReadableText.dump_options(mod, '   ')
    print("\nModule options (#{mod.fullname}):\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

    # If it's an exploit and a payload is defined, create it and
    # display the payload's options
    if ((mod.exploit? or mod.evasion? ) and mod.datastore['PAYLOAD'])
      p = framework.payloads.create(mod.datastore['PAYLOAD'])

      if (!p)
        print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
        return
      end

      p.share_datastore(mod.datastore)

      if (p)
        p_opt = Serializer::ReadableText.dump_options(p, '   ')
        print("\nPayload options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
        print("   **DisablePayloadHandler: True   (payload settings will be ignored!)**\n\n") if mod.datastore['DisablePayloadHandler'].to_s == 'true'
      end
    end

    # Print the selected target
    if (mod.exploit? and mod.target)
      mod_targ = Serializer::ReadableText.dump_exploit_target(mod, '   ')
      print("\nExploit target:\n\n#{mod_targ}\n") if (mod_targ and mod_targ.length > 0)
    elsif mod.evasion? and mod.target
      mod_targ = Serializer::ReadableText.dump_evasion_target(mod, '   ')
      print("\nEvasion target:\n\n#{mod_targ}\n") if (mod_targ and mod_targ.length > 0)
    end

    # Print the selected action
    if mod.kind_of?(Msf::Module::HasActions) && mod.action
      mod_action = Serializer::ReadableText.dump_module_action(mod, '   ')
      print("\n#{mod.type.capitalize} action:\n\n#{mod_action}\n") if (mod_action and mod_action.length > 0)
    end

    # Uncomment this line if u want target like msf2 format
    #print("\nTarget: #{mod.target.name}\n\n")
  end

  # This is for the "use" and "set" commands
  def index_from_list(list, index, &block)
    return unless list.kind_of?(Array) && index

    begin
      idx = Integer(index)
    rescue ArgumentError
      return
    end

    # Don't support negative indices
    return if idx < 0

    yield list[idx]
  end

end

end
end
end
end
