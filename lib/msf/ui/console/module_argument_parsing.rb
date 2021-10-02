# -*- coding: binary -*-

require 'addressable'
require 'msf/ui/console/command_dispatcher'

module Msf
module Ui
module Console

###
#
# A centralized mixin to ensure that options are consistently parsed across all module types
# when running a module's cmd_run/cmd_check/cmd_exploit arguments
#
###
module ModuleArgumentParsing

  # Options which are standard and predictable across all modules
  @@module_opts = Rex::Parser::Arguments.new(
    '-h' => [ false, 'Help banner.'                                          ],
    '-j' => [ false, 'Run in the context of a job.'                          ],
    '-J' => [ false, 'Force running in the foreground, even if passive.'     ],
    '-o' => [ true,  'A comma separated list of options in VAR=VAL format.'  ],
    '-q' => [ false, 'Run the module in quiet mode with no output'           ]
  )

  @@module_opts_with_action_support = Rex::Parser::Arguments.new(@@module_opts.fmt.merge(
    '-a' => [ true, 'The action to use. If none is specified, ACTION is used.']
  ))

  @@exploit_opts = Rex::Parser::Arguments.new(@@module_opts.fmt.merge(
    '-e' => [ true,  'The payload encoder to use.  If none is specified, ENCODER is used.' ],
    '-f' => [ false, 'Force the exploit to run regardless of the value of MinimumRank.'    ],
    '-n' => [ true,  'The NOP generator to use.  If none is specified, NOP is used.'       ],
    '-p' => [ true,  'The payload to use.  If none is specified, PAYLOAD is used.'         ],
    '-t' => [ true,  'The target index to use.  If none is specified, TARGET is used.'     ],
    '-z' => [ false, 'Do not interact with the session after successful exploitation.'     ]
  ))

  def parse_check_opts(args)
    help_cmd = proc do |_result|
      cmd_check_help
    end
    parse_opts(@@module_opts_with_action_support, args, help_cmd: help_cmd)&.slice(:datastore_options)
  end

  def parse_run_opts(args, action: nil)
    help_cmd = proc do |result|
      if result[:action].nil?
        cmd_run_help
      else
        cmd_action_help(action)
      end
    end

    parse_opts(@@module_opts_with_action_support, args, help_cmd: help_cmd, action: action)
  end

  def parse_exploit_opts(args)
    help_cmd = proc do |_result|
      cmd_exploit_help
    end
    parse_opts(@@exploit_opts, args, help_cmd: help_cmd)&.except(:action)
  end

  def print_module_run_or_check_usage(command:, description: nil, options: @@module_opts)
    description ||= command == :check ? 'Check if the target is vulnerable' : "Run the current #{name.downcase} module"

    is_http_mod = mod.is_a?(Msf::Exploit::Remote::HttpClient)
    is_smb_mod = mod.is_a?(Msf::Exploit::Remote::SMB::Client) || mod.options.include?('SMBUser')
    is_mysql_mod = mod.is_a?(Msf::Exploit::Remote::MYSQL)

    print_line("Usage: #{command} [options] [RHOSTS]")
    print_line('')
    print_line(description)
    print_line(options.usage)
    print_line('Examples:')
    print_line('')
    print_line("    #{command} 192.168.1.123")
    print_line("    #{command} 192.168.1.1-192.168.1.254")
    print_line("    #{command} file:///tmp/rhost_list.txt")
    print_line("    #{command} http://192.168.1.123/foo") if is_http_mod
    print_line("    #{command} http://user:pass@192.168.1.123/foo") if is_http_mod
    print_line("    #{command} HttpTrace=true http://192.168.1.123/foo") if is_http_mod
    print_line("    #{command} mysql://user:pass@192.168.1.123") if is_mysql_mod
    print_line("    #{command} SQL='select version()' mysql://user:pass@192.168.1.123") if is_mysql_mod && mod.options.include?('SQL')
    print_line("    #{command} smb://192.168.1.123") if is_smb_mod
    print_line("    #{command} smb://user:pass@192.168.1.123") if is_smb_mod
    print_line("    #{command} LPATH=/tmp/foo.txt smb://user:pass@192.168.1.123/share_name/foo.txt") if is_smb_mod && mod.options.include?('RPATH')
    print_line('')
    print_line('Learn more at https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit')
    print_line('')
  end

  protected

  def parse_opts(opts, args, help_cmd:, action: nil)
    result = {
      jobify: false,
      quiet: false,
      datastore_options: {},
      action: action || mod.datastore['ACTION']
    }
    datastore_options = result[:datastore_options]
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-e'
        result[:encoder] = val
      when '-f'
        result[:force] = true
      when '-j'
        result[:jobify] = true
      when '-J'
        result[:jobify] = false
      when '-n'
        result[:nop] = val
      when '-o'
        if val.nil?
          print_error('Missing OptionStr value')
          help_cmd.call result
          return
        end
        val << '=' unless val.include?('=')
        val.split(',').each do |opt|
          name, value = opt.split('=', 2)
          append_datastore_option(datastore_options, name, value)
        end
      when '-p'
        result[:payload] = val
      when '-t'
        result[:target] = val.to_i
      when '-z'
        result[:background] = true
      when '-a'
        result[:action] = val
      when '-q'
        result[:quiet] = true
      when '-h'
        help_cmd.call result
        return
      else
        if val && val[0] == '-'
          help_cmd.call result
          return
        end

        if resembles_datastore_assignment?(val)
          name, val = val.split('=', 2)
          append_datastore_option(datastore_options, name, val)
        elsif resembles_rhost_value?(val)
          append_datastore_option(datastore_options, 'RHOSTS', val)
        else
          print_error("Invalid argument #{val}")
          help_cmd.call result
          return
        end
      end
    end

    result
  end

  def resembles_datastore_assignment?(val)
    return false unless val

    valid_option_regex = /^\w+=.*/
    valid_option_regex.match?(val)
  end

  def resembles_rhost_value?(val)
    return false unless val

    ::Addressable::URI.parse(val)
    true
  rescue ::Addressable::URI::InvalidURIError => _e
    false
  end

  def append_datastore_option(datastore_options, name, value)
    if name.casecmp?('RHOST') || name.casecmp?('RHOSTS')
      new_value = quote_whitespaced_value(value)
      if !datastore_options['RHOSTS']
        datastore_options['RHOSTS'] = new_value
      else
        datastore_options['RHOSTS'] = "#{datastore_options['RHOSTS']} #{new_value}"
      end
    else
      datastore_options[name.upcase] = value
    end
    datastore_options
  end

  # Wraps values which contain spaces in quotes to ensure it's handled correctly later
  def quote_whitespaced_value(val)
    val.include?(' ') ? "\"#{val}\"" : val
  end
end
end
end
end
