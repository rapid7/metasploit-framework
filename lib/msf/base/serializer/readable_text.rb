# -*- coding: binary -*-
module Msf
module Serializer

# This class formats information in a plain-text format that
# is meant to be displayed on a console or some other non-GUI
# medium.
class ReadableText

  #Default number of characters to wrap at.
  DefaultColumnWrap = 70
  #Default number of characters to indent.
  DefaultIndent     = 2

  # Returns a formatted string that contains information about
  # the supplied module instance.
  #
  # @param mod [Msf::Module] the module to dump information for.
  # @param indent [String] the indentation to use.
  # @return [String] formatted text output of the dump.
  def self.dump_module(mod, indent = "  ")
    case mod.type
      when Msf::MODULE_PAYLOAD
        return dump_payload_module(mod, indent)
      when Msf::MODULE_NOP
        return dump_basic_module(mod, indent)
      when Msf::MODULE_ENCODER
        return dump_basic_module(mod, indent)
      when Msf::MODULE_EXPLOIT
        return dump_exploit_module(mod, indent)
      when Msf::MODULE_AUX
        return dump_auxiliary_module(mod, indent)
      when Msf::MODULE_POST
        return dump_post_module(mod, indent)
      else
        return dump_generic_module(mod, indent)
    end
  end

  # Dumps an exploit's targets.
  #
  # @param mod [Msf::Exploit] the exploit module to dump targets
  #   for.
  # @param indent [String] the indentation to use (only the length
  #   matters).
  # @param h [String] the string to display as the table heading.
  # @return [String] the string form of the table.
  def self.dump_exploit_targets(mod, indent = '', h = nil)
    tbl = Rex::Text::Table.new(
      'Indent'  => indent.length,
      'Header'  => h,
      'Columns' =>
        [
          'Id',
          'Name',
        ])

    mod.targets.each_with_index { |target, idx|
      tbl << [ idx.to_s, target.name || 'All' ]
    }

    tbl.to_s + "\n"
  end

  # Dumps the exploit's selected target
  #
  # @param mod [Msf::Exploit] the exploit module.
  # @param indent [String] the indentation to use (only the length
  #   matters)
  # @param h [String] the string to display as the table heading.
  # @return [String] the string form of the table.
  def self.dump_exploit_target(mod, indent = '', h = nil)
    tbl = Rex::Text::Table.new(
      'Indent'  => indent.length,
      'Header'  => h,
      'Columns' =>
        [
          'Id',
          'Name',
        ])

    tbl << [ mod.target_index, mod.target.name || 'All' ]

    tbl.to_s + "\n"
  end

  # Dumps a module's actions
  #
  # @param mod [Msf::Module] the module.
  # @param indent [String] the indentation to use (only the length
  #   matters)
  # @param h [String] the string to display as the table heading.
  # @return [String] the string form of the table.
  def self.dump_module_actions(mod, indent = '', h = nil)
    tbl = Rex::Text::Table.new(
      'Indent'  => indent.length,
      'Header'  => h,
      'Columns' =>
        [
          'Name',
          'Description'
        ])

    mod.actions.each_with_index { |target, idx|
      tbl << [ target.name || 'All' , target.description || '' ]
    }

    tbl.to_s + "\n"
  end

  # Dumps the module's selected action
  #
  # @param mod [Msf::Module] the module.
  # @param indent [String] the indentation to use (only the length
  #   matters)
  # @param h [String] the string to display as the table heading.
  # @return [String] the string form of the table.
  def self.dump_module_action(mod, indent = '', h = nil)
    tbl = Rex::Text::Table.new(
      'Indent'  => indent.length,
      'Header'  => h,
      'Columns' =>
        [
          'Name',
          'Description',
        ])

    tbl << [ mod.action.name || 'All', mod.action.description || '' ]

    tbl.to_s + "\n"
  end

  # Dumps the table of payloads that are compatible with the supplied
  # exploit.
  #
  # @param exploit [Msf::Exploit] the exploit module.
  # @param indent [String] the indentation to use (only the length
  #   matters)
  # @param h [String] the string to display as the table heading.
  # @return [String] the string form of the table.
  def self.dump_compatible_payloads(exploit, indent = '', h = nil)
    tbl = Rex::Text::Table.new(
      'Indent'  => indent.length,
      'Header'  => h,
      'Columns' =>
        [
          'Name',
          'Description',
        ])

    exploit.compatible_payloads.each { |entry|
      tbl << [ entry[0], entry[1].new.description ]
    }

    tbl.to_s + "\n"
  end

  # Dumps information about an exploit module.
  #
  # @param mod [Msf::Exploit] the exploit module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_exploit_module(mod, indent = '')
    output  = "\n"
    output << "       Name: #{mod.name}\n"
    output << "     Module: #{mod.fullname}\n"
    output << "   Platform: #{mod.platform_to_s}\n"
    output << " Privileged: " + (mod.privileged? ? "Yes" : "No") + "\n"
    output << "    License: #{mod.license}\n"
    output << "       Rank: #{mod.rank_to_s.capitalize}\n"
    output << "  Disclosed: #{mod.disclosure_date}\n" if mod.disclosure_date
    output << "\n"

    # Authors
    output << "Provided by:\n"
    mod.each_author { |author|
      output << indent + author.to_s + "\n"
    }
    output << "\n"

    # Targets
    output << "Available targets:\n"
    output << dump_exploit_targets(mod, indent)

    # Options
    if (mod.options.has_options?)
      output << "Basic options:\n"
      output << dump_options(mod, indent)
      output << "\n"
    end

    # Payload information
    if (mod.payload_info.length)
      output << "Payload information:\n"
      if (mod.payload_space)
        output << indent + "Space: " + mod.payload_space.to_s + "\n"
      end
      if (mod.payload_badchars)
        output << indent + "Avoid: " + mod.payload_badchars.length.to_s + " characters\n"
      end
      output << "\n"
    end

    # Description
    output << "Description:\n"
    output << word_wrap(Rex::Text.compress(mod.description))
    output << "\n"

    # References
    output << dump_references(mod, indent)

    return output

  end

  # Dumps information about an auxiliary module.
  #
  # @param mod [Msf::Auxiliary] the auxiliary module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_auxiliary_module(mod, indent = '')
    output  = "\n"
    output << "       Name: #{mod.name}\n"
    output << "     Module: #{mod.fullname}\n"
    output << "    License: #{mod.license}\n"
    output << "       Rank: #{mod.rank_to_s.capitalize}\n"
    output << "  Disclosed: #{mod.disclosure_date}\n" if mod.disclosure_date
    output << "\n"

    # Authors
    output << "Provided by:\n"
    mod.each_author { |author|
      output << indent + author.to_s + "\n"
    }
    output << "\n"

    # Actions
    if mod.action
      output << "Available actions:\n"
      output << dump_module_actions(mod, indent)
    end

    # Options
    if (mod.options.has_options?)
      output << "Basic options:\n"
      output << dump_options(mod, indent)
      output << "\n"
    end

    # Description
    output << "Description:\n"
    output << word_wrap(Rex::Text.compress(mod.description))
    output << "\n"

    # References
    output << dump_references(mod, indent)

    return output
  end

  # Dumps information about a post module.
  #
  # @param mod [Msf::Post] the post module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_post_module(mod, indent = '')
    output  = "\n"
    output << "       Name: #{mod.name}\n"
    output << "     Module: #{mod.fullname}\n"
    output << "   Platform: #{mod.platform_to_s}\n"
    output << "       Arch: #{mod.arch_to_s}\n"
    output << "       Rank: #{mod.rank_to_s.capitalize}\n"
    output << "  Disclosed: #{mod.disclosure_date}\n" if mod.disclosure_date
    output << "\n"

    # Authors
    output << "Provided by:\n"
    mod.each_author { |author|
      output << indent + author.to_s + "\n"
    }
    output << "\n"

    # Actions
    if mod.action
      output << "Available actions:\n"
      output << dump_module_actions(mod, indent)
    end

    # Options
    if (mod.options.has_options?)
      output << "Basic options:\n"
      output << dump_options(mod, indent)
      output << "\n"
    end

    # Description
    output << "Description:\n"
    output << word_wrap(Rex::Text.compress(mod.description))
    output << "\n"

    # References
    output << dump_references(mod, indent)

    return output
  end

  # Dumps information about a payload module.
  #
  # @param mod [Msf::Payload] the payload module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_payload_module(mod, indent = '')
    # General
    output  = "\n"
    output << "       Name: #{mod.name}\n"
    output << "     Module: #{mod.fullname}\n"
    output << "   Platform: #{mod.platform_to_s}\n"
    output << "       Arch: #{mod.arch_to_s}\n"
    output << "Needs Admin: " + (mod.privileged? ? "Yes" : "No") + "\n"
    output << " Total size: #{mod.size}\n"
    output << "       Rank: #{mod.rank_to_s.capitalize}\n"
    output << "\n"

    # Authors
    output << "Provided by:\n"
    mod.each_author { |author|
      output << indent + author.to_s + "\n"
    }
    output << "\n"

    # Options
    if (mod.options.has_options?)
      output << "Basic options:\n"
      output << dump_options(mod)
      output << "\n"
    end

    # Description
    output << "Description:\n"
    output << word_wrap(Rex::Text.compress(mod.description))
    output << "\n\n"

    return output
  end

  # Dumps information about a module, just the basics.
  #
  # @param mod [Msf::Module] the module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_basic_module(mod, indent = '')
    # General
    output  = "\n"
    output << "       Name: #{mod.name}\n"
    output << "     Module: #{mod.fullname}\n"
    output << "   Platform: #{mod.platform_to_s}\n"
    output << "       Arch: #{mod.arch_to_s}\n"
    output << "       Rank: #{mod.rank_to_s.capitalize}\n"
    output << "\n"

    # Authors
    output << "Provided by:\n"
    mod.each_author { |author|
      output << indent + author.to_s + "\n"
    }
    output << "\n"

    # Description
    output << "Description:\n"
    output << word_wrap(Rex::Text.compress(mod.description))
    output << "\n"

    output << dump_references(mod, indent)

    output << "\n"

    return output

  end

  #No current use
  def self.dump_generic_module(mod, indent = '')
  end

  # Dumps the list of options associated with the
  # supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @param indent [String] the indentation to use.
  # @param missing [Boolean] dump only empty required options.
  # @return [String] the string form of the information.
  def self.dump_options(mod, indent = '', missing = false)
    tbl = Rex::Text::Table.new(
      'Indent'  => indent.length,
      'Columns' =>
        [
          'Name',
          'Current Setting',
          'Required',
          'Description'
        ])

    mod.options.sorted.each do |name, opt|
      val = mod.datastore[name].nil? ? opt.default : mod.datastore[name]

      next if (opt.advanced?)
      next if (opt.evasion?)
      next if (missing && opt.valid?(val))

      desc = opt.desc.dup

      # Hint at RPORT proto by regexing mixins
      if name == 'RPORT' && opt.kind_of?(Msf::OptPort)
        mod.class.included_modules.each do |m|
          case m.name
          when /tcp/i, /HttpClient$/
            desc << ' (TCP)'
            break
          when /udp/i
            desc << ' (UDP)'
            break
          end
        end
      end

      tbl << [ name, opt.display_value(val), opt.required? ? "yes" : "no", desc ]
    end

    return tbl.to_s
  end

  # Dumps the advanced options associated with the supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_advanced_options(mod, indent = '')
    tbl = Rex::Text::Table.new(
      'Indent'  => indent.length,
      'Columns' =>
        [
          'Name',
          'Current Setting',
          'Required',
          'Description'
        ])

    mod.options.sorted.each do |name, opt|
      next unless opt.advanced?
      val = mod.datastore[name].nil? ? opt.default : mod.datastore[name]
      tbl << [ name, opt.display_value(val), opt.required? ? "yes" : "no", opt.desc ]
    end

    return tbl.to_s
  end

  # Dumps the evasion options associated with the supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_evasion_options(mod, indent = '')
    tbl = Rex::Text::Table.new(
      'Indent'  => indent.length,
      'Columns' =>
        [
          'Name',
          'Current Setting',
          'Required',
          'Description'
        ])

    mod.options.sorted.each do |name, opt|
      next unless opt.evasion?
      val = mod.datastore[name].nil? ? opt.default : mod.datastore[name]
      tbl << [ name, opt.display_value(val), opt.required? ? "yes" : "no", opt.desc ]
    end

    return tbl.to_s
  end

  # Dumps the references associated with the supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_references(mod, indent = '')
    output = ''

    if (mod.respond_to?(:references) && mod.references && mod.references.length > 0)
      output << "References:\n"
      mod.references.each { |ref|
        output << indent + ref.to_s + "\n"
      }
      output << "\n"
    end

    output
  end

  # Dumps the contents of a datastore.
  #
  # @param name [String] displayed as the table header.
  # @param ds [Msf::DataStore] the DataStore to dump.
  # @param indent [Integer] the indentation size.
  # @param col [Integer] the column width.
  # @return [String] the formatted DataStore contents.
  def self.dump_datastore(name, ds, indent = DefaultIndent, col = DefaultColumnWrap)
    tbl = Rex::Text::Table.new(
      'Indent'  => indent,
      'Header'  => name,
      'Columns' =>
        [
          'Name',
          'Value'
        ])

    ds.keys.sort.each { |k|
      tbl << [ k, (ds[k] != nil) ? ds[k].to_s : '' ]
    }

    return ds.length > 0 ? tbl.to_s : "#{tbl.header_to_s}No entries in data store.\n"
  end

  # Dumps the list of active sessions.
  #
  # @param framework [Msf::Framework] the framework to dump.
  # @param opts [Hash] the options to dump with.
  # @option opts :verbose [Boolean] gives more information if set to
  #   true.
  # @option opts :indent [Integer] set the indentation amount.
  # @return [String] the formatted list of sessions.
  def self.dump_sessions(framework, opts={})
    verbose = opts[:verbose] || false
    show_extended = opts[:show_extended] || false
    indent = opts[:indent] || DefaultIndent

    return dump_sessions_verbose(framework, opts) if verbose

    columns = []
    columns << 'Id'
    columns << 'Type'
    columns << 'Checkin?' if show_extended
    columns << 'Local URI' if show_extended
    columns << 'Information'
    columns << 'Connection'

    tbl = Rex::Text::Table.new(
      'Indent'  => indent,
      'Header'  => "Active sessions",
      'Columns' => columns)

    framework.sessions.each_sorted { |k|
      session = framework.sessions[k]

      sinfo = session.info.to_s
      # Arbitrarily cut it at 80 columns
      if sinfo.length > 80
        sinfo = sinfo[0,77] + "..."
      end

      row = []
      row << session.sid.to_s
      row << session.type.to_s
      if session.respond_to?(:session_type)
        row[-1] << (" " + session.session_type)
      elsif session.respond_to?(:platform)
        row[-1] << (" " + session.platform)
      end

      if show_extended
        if session.respond_to?(:last_checkin) && session.last_checkin
          row << "#{(Time.now.to_i - session.last_checkin.to_i)}s ago"
        else
          row << '?'
        end

        if session.exploit_datastore.has_key?('LURI') && !session.exploit_datastore['LURI'].empty?
          row << " (#{session.exploit_datastore['LURI']})"
        else
          row << '?'
        end
      end

      row << sinfo
      row << session.tunnel_to_s + " (#{session.session_host})"

      tbl << row
    }

    return framework.sessions.length > 0 ? tbl.to_s : "#{tbl.header_to_s}No active sessions.\n"
  end

  # Dumps the list of active sessions in verbose mode
  #
  # @param framework [Msf::Framework] the framework to dump.
  # @param opts [Hash] the options to dump with.
  # @return [String] the formatted list of sessions.
  def self.dump_sessions_verbose(framework, opts={})
    out = "Active sessions\n" +
          "===============\n\n"

    if framework.sessions.length == 0
      out << "No active sessions.\n"
      return out
    end

    framework.sessions.each_sorted do |k|
      session = framework.sessions[k]

      sess_info    = session.info.to_s
      sess_id      = session.sid.to_s
      sess_tunnel  = session.tunnel_to_s + " (#{session.session_host})"
      sess_via     = session.via_exploit.to_s
      sess_type    = session.type.to_s
      sess_uuid    = session.payload_uuid.to_s
      sess_puid    = session.payload_uuid.respond_to?(:puid_hex) ? session.payload_uuid.puid_hex : nil
      sess_luri    = session.exploit_datastore['LURI'] || ""

      sess_checkin = "<none>"
      sess_machine_id = session.machine_id.to_s
      sess_registration = "No"

      if session.respond_to? :platform
        sess_type << (" " + session.platform)
      end

      if session.respond_to?(:last_checkin) && session.last_checkin
        sess_checkin = "#{(Time.now.to_i - session.last_checkin.to_i)}s ago @ #{session.last_checkin.to_s}"
      end

      if session.payload_uuid.respond_to?(:puid_hex) && (uuid_info = framework.uuid_db[sess_puid])
        sess_registration = "Yes"
        if uuid_info['name']
          sess_registration << " - Name=\"#{uuid_info['name']}\""
        end
      end

      out << "  Session ID: #{sess_id}\n"
      out << "        Type: #{sess_type}\n"
      out << "        Info: #{sess_info}\n"
      out << "      Tunnel: #{sess_tunnel}\n"
      out << "         Via: #{sess_via}\n"
      out << "        UUID: #{sess_uuid}\n"
      out << "   MachineID: #{sess_machine_id}\n"
      out << "     CheckIn: #{sess_checkin}\n"
      out << "  Registered: #{sess_registration}\n"
      if !sess_luri.empty?
        out << "        LURI: #{sess_luri}\n"
      end



      out << "\n"
    end

    out << "\n"
    return out
  end

  # Dumps the list of running jobs.
  #
  # @param framework [Msf::Framework] the framework.
  # @param verbose [Boolean] if true, also prints the payload, LPORT, URIPATH
  #   and start time, if they exist, for each job.
  # @param indent [Integer] the indentation amount.
  # @param col [Integer] the column wrap width.
  # @return [String] the formatted list of running jobs.
  def self.dump_jobs(framework, verbose = false, indent = DefaultIndent, col = DefaultColumnWrap)
    columns = [ 'Id', 'Name', "Payload", "Payload opts" ]

    if (verbose)
      columns += [ "URIPATH", "Start Time", "Handler opts" ]
    end

    tbl = Rex::Text::Table.new(
      'Indent'  => indent,
      'Header'  => "Jobs",
      'Columns' => columns
      )

    # jobs are stored as a hash with the keys being a numeric String job_id.
    framework.jobs.keys.sort_by(&:to_i).each do |job_id|
      # Job context is stored as an Array with the 0th element being
      # the running module. If that module is an exploit, ctx will also
      # contain its payload.
      exploit_mod, _payload_mod = framework.jobs[job_id].ctx
      row = []
      row[0] = job_id
      row[1] = framework.jobs[job_id].name

      pinst = exploit_mod.respond_to?(:payload_instance) ? exploit_mod.payload_instance : nil
      payload_uri = ''

      if pinst.nil?
        row[2] = ""
        row[3] = ""
      else
        row[2] = pinst.refname
        row[3] = ""
        if pinst.respond_to?(:payload_uri)
          payload_uri = pinst.payload_uri.strip
          row[3] << payload_uri
        end
        if pinst.respond_to?(:luri)
          row[3] << pinst.luri
        end
      end

      if verbose
        uripath = exploit_mod.get_resource if exploit_mod.respond_to?(:get_resource)
        uripath ||= exploit_mod.datastore['URIPATH']
        row[4] = uripath
        row[5] = framework.jobs[job_id].start_time
        row[6] = ''

        if pinst.respond_to?(:listener_uri)
          listener_uri = pinst.listener_uri.strip
          row[6] = listener_uri unless listener_uri == payload_uri
        end
      end
      tbl << row
    end

    return framework.jobs.keys.length > 0 ? tbl.to_s : "#{tbl.header_to_s}No active jobs.\n"
  end

  # Jacked from Ernest Ellingson <erne [at] powernav.com>, modified
  # a bit to add indention
  #
  # @param str [String] the string to wrap.
  # @param indent [Integer] the indentation amount.
  # @param col [Integer] the column wrap width.
  # @return [String] the wrapped string.
  def self.word_wrap(str, indent = DefaultIndent, col = DefaultColumnWrap)
    return Rex::Text.wordwrap(str, indent, col)
  end

end

end end

