##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'winrm'
require 'winrm/wsmv/write_stdin'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell

  def initialize
    super(
      'Name'           => 'WinRM Command Runner',
      'Description'    => %q{
        This module runs arbitrary Windows commands using the WinRM Service
        },
      'Author'         => [ 'thelightcosine' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('CMD', [ true, "The windows command to run", "ipconfig /all" ]),
        OptString.new('USERNAME', [ true, "The username to authenticate as"]),
        OptString.new('PASSWORD', [ true, "The password to authenticate with"])
      ])
  end

  class RexWinRMConnection < WinRM::Connection
    class MessageFactory < WinRM::PSRP::MessageFactory
      def self.create_pipeline_message(runspace_pool_id, pipeline_id, command)
        WinRM::PSRP::Message.new(
          runspace_pool_id,
          WinRM::PSRP::Message::MESSAGE_TYPES[:create_pipeline],
          XMLTemplate.render('create_pipeline', cmdlet: command[:cmdlet], args: command[:args]),
          pipeline_id
        )
      end
    end

class ShellFactory < WinRM::Shells::ShellFactory
    
      class StdinShell < WinRM::Shells::Cmd
        class ReceiveResponseReader < WinRM::WSMV::ReceiveResponseReader
          # Reads streams and returns decoded output
          # @param wsmv_message [WinRM::WSMV::Base] A wsmv message to send to endpoint
          # @yieldparam [string] standard out response text
          # @yieldparam [string] standard error response text 
          # @yieldreturn [WinRM::Output] The command output                                                           
          def read_output(wsmv_message)
            program_terminated = false
            with_output do |output|                                                                                   
              read_response(wsmv_message, false) do |stream, doc|
                handled_out = handle_stream(stream, output, doc)
                if command_done?(doc, true)
                  program_terminated = true
                end
                yield handled_out if handled_out && block_given?
              end
            end                                                                                                       
            if program_terminated
              print_good("Command done")
            end
          end
        end
        def create_proc
          self.command_id = send_command("powershell.exe",[])
        end
      
        def with_command_shell(input, arguments = [])
          tries ||= 2
      
          open unless shell_id
          create_proc unless command_id
          send_stdin(input)
          yield shell_id, self.command_id
        rescue WinRM::WinRMWSManFault => e
          raise unless FAULTS_FOR_RESET.include?(e.fault_code) && (tries -= 1) > 0
      
          reset_on_error(e)
          retry
        end
      
        def send_stdin(input)
          stdin_msg = WinRM::WSMV::WriteStdin.new(
            connection_opts, 
            shell_uri: shell_uri,
            shell_id: shell_id,
            command_id: command_id,
            stdin: input
          )
          result = transport.send_request(stdin_msg.build)
          result
        rescue WinRM::WinRMWSManFault => e
          raise unless [ERROR_OPERATION_ABORTED, SHELL_NOT_FOUND].include?(e.fault_code)
        rescue WinRM::WinRMHTTPTransportError => t
          # dont let the cleanup raise so we dont lose any errors from the command
          logger.info("[WinRM] #{t.status_code} returned in cleanup with error: #{t.message}")
        end

        def response_reader
          @response_reader ||= ReceiveResponseReader.new(transport, logger)
        end

        protected
          attr_accessor :command_id
      end
    
      def create_shell(shell_type, shell_opts = {})
        args = [
          @connection_opts,
          @transport,
          @logger
        ]
        StdinShell.new(*args) if shell_type == :stdin
      end
    end

    class TransportFactory < WinRM::HTTP::TransportFactory
      class RexHttpTransport < WinRM::HTTP::HttpTransport
        # rubocop:disable Lint/
        def initialize(opts)
          self.http_client = Rex::Proto::Http::Client.new(opts[:host], opts[:port], {}, opts[:ssl], opts[:ssl_version], opts[:proxies], opts[:user], opts[:password])

          self.uri = opts[:uri]
        end

        def send_request(message)
          request = self.http_client.request_cgi(
            'uri' => self.uri,
            'method' => 'POST',
            'agent' => 'Microsoft WinRM Client',
            'ctype' => 'application/soap+xml;charset=UTF-8',
            'data' => message
          )
          response = self.http_client.send_recv(request)

          WinRM::ResponseHandler.new(response.body, response.code).parse_to_xml
        end
        protected
          attr_accessor :http_client, :uri
      end

      def create_transport(connection_opts)
        raise NotImplementedError unless connection_opts[:transport] == :rex

        super
      end

      private

      def init_rex_transport(opts)
        RexHttpTransport.new(opts)
      end
    end

    def shell_factory
      @shell_factory ||= ShellFactory.new(@connection_opts, transport, logger)
    end

    def transport
      @transport ||= begin
        transport_factory = TransportFactory.new
        transport_factory.create_transport(@connection_opts)
      end
    end
  end

  def run_host(ip)
    rhost = datastore['RHOST']
    rport = datastore['RPORT']
    uri = datastore['URI']
    ssl = datastore['SSL']
    schema = ssl ? 'https' : 'http'
    endpoint = "#{schema}://#{rhost}:#{rport}#{uri}"
    conn = RexWinRMConnection.new(
                endpoint: endpoint,
                host: rhost,
                port: rport,
                uri: uri,
                ssl: ssl,
                user: datastore['USERNAME'],
                password: datastore['PASSWORD'],
                transport: :rex,
                :no_ssl_peer_verification => true
            )

    shell = conn.shell(:stdin)

    if datastore['CreateSession']
      # Send a meaningless command to determine if the creds are correct
      comment = "##{Rex::Text.rand_text_alpha(16)}"
      shell.run(comment)
      session_setup(shell,rhost,rport,endpoint)
    else
      begin
        path = store_loot("winrm.cmd_results", "text/plain", ip, nil, "winrm_cmd_results.txt", "WinRM CMD Results")
        f = File.open(path,'wb')
        output = shell.run(datastore['CMD']) do |stdout,stderr|
          stdout&.each_line do |line|
            print_line(line.rstrip!)
            f.puts(stdout)
          end
          print_error(stderr) if stderr
        end
        f.close

        print_good "Results saved to #{path}"
      ensure
        shell.close
      end
    end
  end

  def session_setup(shell,rhost,rport,endpoint)
    sess = Msf::Sessions::WinrmCommandShell.new(shell,rhost,rport)
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    info = "WinRM #{username}:#{password} (#{endpoint})"
    merge_me = {
      'USERNAME' => username,
      'PASSWORD' => password
    }

    start_session(self, info, merge_me,false,sess.rstream,sess)
  end


end

