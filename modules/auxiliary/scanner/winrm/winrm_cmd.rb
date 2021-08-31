##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'winrm'

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

  class LogProxy
    def debug(msg)
      print_line(msg)
    end
    def warn(msg)
      vprint_warning(msg)
    end
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

    def initialize(connection_opts)
      super(connection_opts)
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
    endpoint = "#{schema}://#{rhost}:#{rport}/#{uri}"
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

    shell = conn.shell(:powershell)

    if datastore['CreateSession']
      # Send a meaningless command to determine if the creds are correct
      comment = "#{Rex::Text.rand_text_alpha(16)}"
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
    # NEEDED???
    host_info = {os_name: 'Windows'}
    report_host(host_info)
  end


end

