##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'AMQP 0-9-1 Version Scanner',
      'Description' => 'Detect AMQP version information.',
      'Author' => 'Spencer McIntyre',
      'License' => MSF_LICENSE,
      'References' => [
        [ 'URL', 'https://www.rabbitmq.com/amqp-0-9-1-reference.html' ]
      ]
    )

    register_options([
      Opt::RPORT(5671)
    ])

    register_advanced_options(
      [
        OptBool.new('SSL', [ true, 'Negotiate SSL/TLS for outgoing connections', true ]),
        Opt::SSLVersion
      ]
    )
  end

  def peer
    rhost = datastore['RHOST']
    rport = datastore['RPORT']
    if Rex::Socket.is_ipv6?(rhost)
      "[#{rhost}]:#{rport}"
    else
      "#{rhost}:#{rport}"
    end
  end

  def print_prefix
    peer.ljust(21) + ' - '
  end

  def run_host(target_host)
    amqp_client = Rex::Proto::Amqp::Version091::Client.new(
      target_host,
      port: datastore['RPORT'],
      context: { 'Msf' => framework, 'MsfExploit' => self },
      ssl: datastore['SSL'],
      ssl_version: datastore['SSLVersion']
    )

    amqp_client.connect
    amqp_client.send_protocol_header
    amqp_client.recv_connection_start
    server_info = amqp_client.server_info

    info_line = 'AMQP Detected'
    unless server_info[:properties]['product'].blank? || server_info[:properties]['version'].blank?
      info_line << " (version:#{server_info[:properties]['product']} #{server_info[:properties]['version']})"
    end
    unless server_info[:properties]['cluster_name'].blank?
      info_line << " (cluster:#{server_info[:properties]['cluster_name']})"
    end
    unless server_info[:properties]['platform'].blank?
      info_line << " (platform:#{server_info[:properties]['platform']})"
    end
    info_line << " (authentication:#{server_info[:security_mechanisms].join(', ')})"
    print_status(info_line)
    report_service(
      host: target_host,
      port: datastore['RPORT'],
      name: "amqp#{datastore['SSL'] ? 's' : ''}",
      info: info_line
    )
  rescue Rex::Proto::Amqp::Error::UnexpectedReplyError => e
    fail_with(Failure::UnexpectedReply, e.message)
  rescue Rex::Proto::Amqp::Error::AmqpError => e
    fail_with(Failure::Unknown, e.message)
  ensure
    amqp_client.close
  end
end
