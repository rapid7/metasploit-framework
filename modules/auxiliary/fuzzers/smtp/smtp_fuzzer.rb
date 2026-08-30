##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# A Very simple Module to fuzzer some SMTP commands.
# It allows to respect the order or just throw everything at it....
##

require 'English'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Smtp
  include Msf::Auxiliary::Fuzzer
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SMTP Simple Fuzzer',
      'Description' => 'SMTP Simple Fuzzer',
      'References' => [
        ['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
      ],
      'Author' => 'justme',
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SERVICE_DOWN],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options([
      Opt::RPORT(25),
      OptInt.new('STARTLEN', [true, 'Length of the string - start number', 100]),
      OptInt.new('INTERACTIONS', [false, 'Number of interactions to run', 100]),
      OptBool.new('RESPECTORDER', [false, 'Respect order of commands', true]),
      OptEnum.new('CMD', [
        true, 'Command to fuzzer', 'EHLO',
        [
          'EHLO',
          'HELO',
          'MAILFROM',
          'RCPTTO',
          'DATA',
          'VRFY',
          'EXPN'
        ], 'EHLO'
      ])
    ])
  end

  def smtp_send(data = '', con: true)
    @result = ''
    @coderesult = ''
    if con
      @connected = false
      connect
    end
    @connected = true
    sock.put(data)
    @result = sock.get_once
    @codresult = @result[0..2]
  rescue StandardError => e
    print_error(e.to_s)
  end

  def run_host(_ip)
    last_str = nil
    last_inp = nil
    last_err = nil

    cnt = datastore['STARTLEN'] - 1

    1.upto(datastore['INTERACTIONS']) do |interaction|
      cnt += 1

      str = fuzzer_gen_string(cnt)
      cmd = datastore['CMD']

      begin
        if datastore['RESPECTORDER']
          case cmd
          when 'HELO', 'EHLO', 'VRFY', 'EXPN'
            c = datastore['CMD'] + ' ' + str + "\r\n"
            smtp_send(c)
            # print_status(c)
            disconnect

          when 'MAILFROM'
            c = "EHLO localhost\r\n"
            smtp_send(c)
            # print_status(c)
            c = 'MAIL FROM:<' + str + ">\r\n"
            smtp_send(c)
            disconnect
            # print_status(c)
          when 'RCPTTO'
            c = "EHLO localhost\r\n"
            smtp_send(c)
            # print_status(c)
            c = 'MAIL FROM:<' + datastore['MAILFROM'] + ">\r\n"
            smtp_send(c, con: false)
            # print_status(c)
            c = 'RCPT TO:<' + str + ">\r\n"
            smtp_send(c, con: false)
            # print_status(c)
            disconnect
          when 'DATA'
            c = "EHLO localhost\r\n"
            smtp_send(c)
            # print_status(c)
            c = 'MAIL FROM:<' + datastore['MAILFROM'] + ">\r\n"
            smtp_send(c, con: false)
            # print_status(c)
            c = 'RCPT TO:<' + datastore['MAILTO'] + ">\r\n"
            smtp_send(c, con: false)
            # print_status(c)
            c = "DATA \r\n"
            smtp_send(c, con: false)
            c = str + "\r\n.\r\n"
            smtp_send(c, con: false)
            # print_status(c)
            disconnect
          end
        else
          c = datastore['CMD'] + ' ' + str + "\r\n"
          smtp_send(c)
          # print_status(c)
          disconnect
        end

        print_status("Fuzzing with iteration #{interaction}\n #{@result}")
      rescue ::Interrupt
        print_status("Exiting on interrupt: iteration #{interaction} using string  #{str}")
        raise $ERROR_INFO
      rescue StandardError => e
        last_err = e
        # ensure
        # disconnect
      end

      if !@connected
        if last_str
          print_status("The service may have crashed: iteration:#{interection - 1} String=''#{last_str}'' error=#{last_err}")
        else
          print_status("Could not connect to the service: #{last_err}")
        end
        break
      end

      last_str = str
      last_inp = @last_fuzzer_input
    end
  end
end
