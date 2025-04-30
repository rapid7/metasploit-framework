##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Manage Post Module Macro Execution',
        'Description' => %q{
          This module will execute a list of modules given in a macro file in the format
          of <module> <opt=val,opt=val> against the select session checking for compatibility
          of the module against the sessions and validation of the options provided.
        },
        'License' => MSF_LICENSE,
        'Author' => [ '<carlos_perez[at]darkoperator.com>'],
        'Platform' => %w[linux osx solaris unix win],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('MACRO', [true, 'File with Post Modules and Options to run in the session', nil])
      ]
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    macro = datastore['MACRO']

    fail_with(Failure::BadConfig, 'Resource File does not exist!') unless ::File.exist?(macro)

    entries = []

    ::File.open(macro, 'rb').each_line do |line|
      # Empty line
      next if line.strip.empty?
      # Comment
      next if line[0, 1] == '#'

      entries << line.chomp
    end

    fail_with(Failure::BadConfig, 'Resource File was empty!') if entries.blank?

    entries.each do |l|
      values = l.split(' ')
      post_mod = values[0]
      if values.length == 2
        mod_opts = values[1].split(',')
      end
      print_line("Loading #{post_mod}")
      # Make sure we can handle post module names with or without post in the start
      if post_mod =~ %r{^post/}
        post_mod.gsub!(%r{^post/}, '')
      end
      m = framework.post.create(post_mod)

      # Check if a post module was actually initiated
      if m.nil?
        print_error("Post module #{post_mod} could not be initialized!")
        next
      end

      # Set the current session
      s = datastore['SESSION']

      if !m.session_compatible?(s.to_i)
        print_error("Session #{s} is not compatible with #{post_mod}")
        next
      end

      print_line("Running Against #{s}")
      m.datastore['SESSION'] = s
      if mod_opts
        mod_opts.each do |o|
          opt_pair = o.split('=', 2)
          print_line("\tSetting Option #{opt_pair[0]} to #{opt_pair[1]}")
          m.datastore[opt_pair[0]] = opt_pair[1]
        end
      end
      m.options.validate(m.datastore)
      m.run_simple(
        'LocalInput' => user_input,
        'LocalOutput' => user_output
      )
    end
  end
end
