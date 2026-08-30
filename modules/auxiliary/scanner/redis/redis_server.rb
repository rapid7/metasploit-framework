##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Redis
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Redis Command Execute Scanner',
        'Description' => %q{
          This module locates Redis endpoints by attempting to run a specified
          Redis command.
        },
        'Author' => [ 'iallison <ian[at]team-allison.com>', 'Nixawk' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        Opt::RPORT(6379),
        OptString.new('COMMAND', [ true, 'The Redis command to run', 'INFO' ])
      ]
    )
  end

  def command
    datastore['COMMAND']
  end

  def run_host(_ip)
    vprint_status('Contacting redis')
    begin
      connect
      command_parts = command.split(' ')
      return unless (raw_data = redis_command(*command_parts))

      report_service(host: rhost, port: rport, name: 'redis server', info: "#{command} response: #{printable_redis_response(raw_data)}")
      print_good("Found redis with #{command} command")
      begin
        print_line(parse_redis_info(raw_data))
      rescue StandardError => e
        print_error("Failed to parse INFO response (#{e.class}: #{e.message}); raw response: #{printable_redis_response(raw_data)}")
      end
    rescue Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout,
           Rex::ConnectionRefused, ::Timeout::Error, ::EOFError, ::Errno::ETIMEDOUT => e
      vprint_error("Error while communicating: #{e}")
    ensure
      disconnect
    end
  end

  def parse_redis_info(raw_data)
    # Strip Redis bulk-string length prefix ($NNNN\r\n) if present
    data = raw_data.sub(/\A\$\d+\r\n/, '')

    sections = {}
    current = nil

    data.split("\r\n").each do |line|
      next if line.empty?

      if line.start_with?('# ')
        current = line[2..]
        sections[current] = []
      elsif current && (colon = line.index(':'))
        sections[current] << [line[0, colon], line[colon + 1..]]
      end
    end

    return printable_redis_response(raw_data) if sections.empty?

    out = +''
    sections.each do |section, pairs|
      next if pairs.empty?

      tbl = Rex::Text::Table.new(
        'Header' => section,
        'Indent' => 2,
        'Columns' => %w[Key Value]
      )
      pairs.each { |k, v| tbl << [k, v] }
      out << tbl.to_s << "\n"
    end
    out
  end
end
