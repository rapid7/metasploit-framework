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
      dump_payload_module(mod, indent)
    when Msf::MODULE_NOP
      dump_basic_module(mod, indent)
    when Msf::MODULE_ENCODER
      dump_basic_module(mod, indent)
    when Msf::MODULE_EXPLOIT
      dump_exploit_module(mod, indent)
    when Msf::MODULE_AUX
      dump_auxiliary_module(mod, indent)
    when Msf::MODULE_POST
      dump_post_module(mod, indent)
    when Msf::MODULE_EVASION
      dump_evasion_module(mod, indent)
    else
      dump_generic_module(mod, indent)
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

  def self.dump_evasion_targets(mod, indent = '', h = nil)
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

  # Dumps the evasion module's selected target
  #
  # @param mod [Msf::Evasion] The evasion module.
  # @param indent [String] The indentation to use (only the length matters)
  # @param h [String] The string to display as the table heading.
  # @return [String] The strong form of the table.
  def self.dump_evasion_target(mod, indent = '', h = nil)
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

  def self.dump_traits(mod, indent=' ')
    output = ''

    unless mod.stability.empty?
      output << "Module stability:\n"
      mod.stability.each { |stability|
        output << indent + stability + "\n"
      }
      output << "\n"
    end

    unless mod.reliability.empty?
      output << "Module reliability:\n"
      mod.reliability.each { |reliability|
        output << indent + reliability + "\n"
      }
      output << "\n"
    end

    unless mod.side_effects.empty?
      output << "Module side effects:\n"
      mod.side_effects.each { |side_effect|
        output << indent + side_effect + "\n"
      }
      output << "\n"
    end

    output
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
    output << "       Arch: #{mod.arch_to_s}\n"
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

    # Check
    output << "Check supported:\n"
    output << "#{indent}#{mod.respond_to?(:check) ? 'Yes' : 'No'}\n\n"

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

    # Traits
    output << dump_traits(mod, indent)

    # Notes
    output << dump_notes(mod, indent)

    output
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

    # Check
    output << "Check supported:\n"
    output << "#{indent}#{mod.respond_to?(:check) ? 'Yes' : 'No'}\n\n"

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

    # Traits
    output << dump_traits(mod, indent)

    # Notes
    output << dump_notes(mod, indent)

    output
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
    mod.each_author.each do |author|
      output << indent + author.to_s + "\n"
    end
    output << "\n"

    # Compatible session types
    if mod.session_types
      output << "Compatible session types:\n"
      mod.session_types.sort.each do |type|
        output << indent + type.capitalize + "\n"
      end
      output << "\n"
    end

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

    # Traits
    output << dump_traits(mod, indent)

    # Notes
    output << dump_notes(mod, indent)

    output
  end

  # Dumps information about an evasion module.
  #
  # @param mod [Msf::Evasion] The evasion module instance.
  # @param indent [String] The indentation to use.
  # @return [String] The string form of the information
  def self.dump_evasion_module(mod, indent = '')
    output  = "\n"
    output << "       Name: #{mod.name}\n"
    output << "     Module: #{mod.fullname}\n"
    output << "   Platform: #{mod.platform_to_s}\n"
    output << "       Arch: #{mod.arch_to_s}\n"
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

    # Check
    output << "Check supported:\n"
    output << "#{indent}#{mod.respond_to?(:check) ? 'Yes' : 'No'}\n\n"

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

    output
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

    output
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

    # References
    output << dump_references(mod, indent)

    # Traits
    output << dump_traits(mod, indent)

    # Notes
    output << dump_notes(mod, indent)

    output
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

    tbl.to_s
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

    tbl.to_s
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

    tbl.to_s
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

      mod.references.each do |ref|
        case ref.ctx_id
        when 'LOGO', 'SOUNDTRACK'
          output << indent + ref.to_s + "\n"
          Rex::Compat.open_browser(ref.ctx_val) if Rex::Compat.getenv('FUEL_THE_HYPE_MACHINE')
        else
          output << indent + ref.to_s + "\n"
        end
      end

      output << "\n"
    end

    output
  end

  # Dumps the notes associated with the supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @param indent [String] the indentation to use.
  # @return [String] the string form of the information.
  def self.dump_notes(mod, indent = '')
    output = ''

    mod.notes.each do |name, val|
      next unless val.present?

      case name
      when 'AKA'
        output << "Also known as:\n"
        val.each { |aka| output << "#{indent}#{aka}\n" }
      when 'NOCVE'
        output << "CVE not available for the following reason:\n" \
                  "#{indent}#{val}\n"
      when 'RelatedModules'
        output << "Related modules:\n"
        val.each { |related| output << "#{indent}#{related}\n" }
      when 'Stability', 'Reliability', 'SideEffects'
        # Handled by dump_traits
        next
      else
        output << "#{name}:\n"

        case val
        when Array
          val.each { |v| output << "#{indent}#{v}\n" }
        when Hash
          val.each { |k, v| output << "#{indent}#{k}: #{v}\n" }
        else
          # Display the raw note
          output << "#{indent}#{val}\n"
        end
      end

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

    ds.length > 0 ? tbl.to_s : "#{tbl.header_to_s}No entries in data store.\n"
  end

  # Dumps the list of sessions.
  #
  # @param framework [Msf::Framework] the framework to dump.
  # @param opts [Hash] the options to dump with.
  # @option opts :verbose [Boolean] gives more information if set to
  #   true.
  # @option opts :indent [Integer] set the indentation amount.
  # @return [String] the formatted list of sessions.
  def self.dump_sessions(framework, opts={})
    output = ""
    verbose = opts[:verbose] || false
    show_active = opts[:show_active] || false
    show_inactive = opts[:show_inactive] || false
    # if show_active and show_inactive are false the caller didn't
    # specify either flag; default to displaying active sessions
    show_active = true if !(show_active || show_inactive)
    show_extended = opts[:show_extended] || false
    indent = opts[:indent] || DefaultIndent

    return dump_sessions_verbose(framework, opts) if verbose

    if show_active
      columns = []
      columns << 'Id'
      columns << 'Name'
      columns << 'Type'
      columns << 'Checkin?' if show_extended
      columns << 'Enc?' if show_extended
      columns << 'Local URI' if show_extended
      columns << 'Information'
      columns << 'Connection'

      tbl = Rex::Text::Table.new(
          'Header' => "Active sessions",
          'Columns' => columns,
          'Indent' => indent)
      framework.sessions.each_sorted { |k|
        session = framework.sessions[k]
        row = create_msf_session_row(session, show_extended)
        tbl << row
      }

      output << (tbl.rows.count > 0 ? tbl.to_s : "#{tbl.header_to_s}No active sessions.\n")
    end

    if show_inactive
      output << "\n" if show_active

      columns = []
      columns << 'Closed'
      columns << 'Opened'
      columns << 'Reason Closed'
      columns << 'Type'
      columns << 'Address'

      tbl = Rex::Text::Table.new(
          'Header' => "Inactive sessions",
          'Columns' => columns,
          'Indent' => indent,
          'SortIndex' => 1)

      if framework.db.active
        framework.db.sessions.each do |session|
          unless session.closed_at.nil?
            row = create_mdm_session_row(session, show_extended)
            tbl << row
          end
        end
      end

      output << (tbl.rows.count > 0 ? tbl.to_s : "#{tbl.header_to_s}No inactive sessions.\n")
    end

    # return formatted listing of sessions
    output
  end

  # Creates a table row that represents the specified session.
  #
  # @param session [Msf::Session] session used to create a table row.
  # @param show_extended [Boolean] Indicates if extended information will be included in the row.
  # @return [Array] table row of session data.
  def self.create_msf_session_row(session, show_extended)
    row = []
    row << session.sid.to_s
    row << session.sname.to_s
    row << session.type.to_s
    if session.respond_to?(:session_type)
      row[-1] << " #{session.session_type}"
    elsif session.respond_to?(:platform)
      row[-1] << " #{session.platform}"
    end

    if show_extended
      if session.respond_to?(:last_checkin) && session.last_checkin
        row << "#{(Time.now.to_i - session.last_checkin.to_i)}s ago"
      else
        row << '?'
      end

      if session.respond_to?(:tlv_enc_key) && session.tlv_enc_key && session.tlv_enc_key[:key]
        row << 'Y'
      else
        row << 'N'
      end

      if session.exploit_datastore && session.exploit_datastore.has_key?('LURI') && !session.exploit_datastore['LURI'].empty?
        row << "(#{session.exploit_datastore['LURI']})"
      else
        row << '?'
      end
    end

    sinfo = session.info.to_s
    # Arbitrarily cut info at 80 columns
    if sinfo.length > 80
      sinfo = "#{sinfo[0,77]}..."
    end
    row << sinfo

    row << "#{session.tunnel_to_s} (#{session.session_host})"

    # return complete row
    row
  end

  # Creates a table row that represents the specified session.
  #
  # @param session [Mdm::Session] session used to create a table row.
  # @param show_extended [Boolean] Indicates if extended information will be included in the row.
  # @return [Array] table row of session data.
  def self.create_mdm_session_row(session, show_extended)
    row = []
    row << session.closed_at.to_s
    row << session.opened_at.to_s
    row << session.close_reason
    row << session.stype
    if session.respond_to?(:platform) && !session.platform.nil?
      row[-1] << " #{session.platform}"
    end
    row << (!session.host.nil? ? session.host.address : nil)

    # return complete row
    row
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
      sess_name    = session.sname.to_s
      sess_tunnel  = session.tunnel_to_s + " (#{session.session_host})"
      sess_via     = session.via_exploit.to_s
      sess_type    = session.type.to_s
      sess_uuid    = session.payload_uuid.to_s
      sess_luri    = session.exploit_datastore['LURI'] || "" if session.exploit_datastore
      sess_enc     = false
      if session.respond_to?(:tlv_enc_key) && session.tlv_enc_key && session.tlv_enc_key[:key]
        sess_enc   = true
      end

      sess_checkin = "<none>"
      sess_registration = "No"

      if session.respond_to?(:platform) && session.platform
        sess_type << " #{session.platform}"
      end

      if session.respond_to?(:last_checkin) && session.last_checkin
        sess_checkin = "#{(Time.now.to_i - session.last_checkin.to_i)}s ago @ #{session.last_checkin.to_s}"
      end

      if !session.payload_uuid.nil? && session.payload_uuid.registered
        sess_registration = "Yes"
        if session.payload_uuid.name
          sess_registration << " - Name=\"#{session.payload_uuid.name}\""
        end
      end

      out << "  Session ID: #{sess_id}\n"
      out << "        Name: #{sess_name}\n"
      out << "        Type: #{sess_type}\n"
      out << "        Info: #{sess_info}\n"
      out << "      Tunnel: #{sess_tunnel}\n"
      out << "         Via: #{sess_via}\n"
      out << "   Encrypted: #{sess_enc}\n"
      out << "        UUID: #{sess_uuid}\n"
      out << "     CheckIn: #{sess_checkin}\n"
      out << "  Registered: #{sess_registration}\n"
      unless (sess_luri || '').empty?
        out << "        LURI: #{sess_luri}\n"
      end

      out << "\n"
    end

    out << "\n"

    out
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
    columns = [ 'Id', 'Name', "Payload", "Payload opts"]

    if (verbose)
      columns += [ "URIPATH", "Start Time", "Handler opts", "Persist" ]
    end

    tbl = Rex::Text::Table.new(
      'Indent'  => indent,
      'Header'  => "Jobs",
      'Columns' => columns
      )

    # Get the persistent job info.
    if verbose
      begin
        persist_list = JSON.parse(File.read(Msf::Config.persist_file))
      rescue Errno::ENOENT, JSON::ParserError
        persist_list = []
      end
    end

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
        row[7] = 'false'

        if pinst.respond_to?(:listener_uri)
          listener_uri = pinst.listener_uri.strip
          row[6] = listener_uri unless listener_uri == payload_uri
        end

        persist_list.each do |e|
          if framework.jobs[job_id.to_s].ctx[1]
             row[7] = 'true' if e['mod_options']['Options'] == framework.jobs[job_id.to_s].ctx[1].datastore
          end
        end

      end
      tbl << row
    end

    framework.jobs.keys.length > 0 ? tbl.to_s : "#{tbl.header_to_s}No active jobs.\n"
  end

  # Jacked from Ernest Ellingson <erne [at] powernav.com>, modified
  # a bit to add indention
  #
  # @param str [String] the string to wrap.
  # @param indent [Integer] the indentation amount.
  # @param col [Integer] the column wrap width.
  # @return [String] the wrapped string.
  def self.word_wrap(str, indent = DefaultIndent, col = DefaultColumnWrap)
    Rex::Text.wordwrap(str, indent, col)
  end

end

end
end
