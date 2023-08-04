# -*- coding: binary -*-
module Msf
module Handler

require 'aws-sdk-ec2instanceconnect'
require 'net/ssh'
require 'net/ssh/command_stream'
require 'rex/socket/ssh_factory'

###
#
# This module implements the AWS InstanceConnect handler.  This means that
# it will attempt to connect to a remote host through the AWS InstanceConnect pipe for
# a period of time (typically the duration of an exploit) to see if the  agent has
# started listening.
#
###
module BindAwsInstanceConnect
  include Msf::Handler
  #
  # Returns the handler specific string representation, in this case
  # 'bind_aws_instance_connect'.
  #
  def self.handler_type
    'bind_aws_instance_connect'
  end

  #
  # Returns the connection oriented general handler type, in this case bind.
  #
  def self.general_handler_type
    'bind'
  end

  # A string suitable for displaying to the user
  #
  # @return [String]
  def human_name
    'bind AWS InstanceConnect'
  end

  #
  # Initializes a bind handler and adds the options common to all bind
  # payloads, such as local port.
  #
  def initialize(info = {})
    super

    register_options(
      [
        OptString.new('EC2_ID', [true, 'The EC2 ID of the instance ', '']),
        OptString.new('REGION', [true, 'AWS region containing the instance', 'us-east-1']),
        OptString.new('ACCESS_KEY_ID', [false, 'AWS access key', nil]),
        OptString.new('SECRET_ACCESS_KEY', [false, 'AWS secret key', nil]),
        OptString.new('INSTANCE_USER', [false, 'Username on the EC2 instance with which to log-in']),
        OptString.new('ROLE_ARN', [false, 'AWS assumed role ARN', nil]),
        OptString.new('ROLE_SID', [false, 'AWS assumed role session ID', nil]),
        OptString.new('USERNAME', [false, 'EC2 instance local username to authenticate with']),
        OptString.new('PASSWORD', [false, 'EC2 instance local password to authenticate with'])
      ], Msf::Handler::BindAwsInstanceConnect)

    register_advanced_options(
      [
        OptString.new('PRIVATE_KEY', [
          false,
          'The string value of the private key that will be used. If you are using MSFConsole,
          this value should be set as file:PRIVATE_KEY_PATH. OpenSSH, RSA, DSA, and ECDSA private keys are supported.'
        ]),
        OptString.new('KEY_PASS', [false, 'Passphrase for SSH private key(s)']),
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false])
      ], Msf::Handler::BindAwsInstanceConnect)

    self.listener_threads = []
    self.conn_threads = []
    self.listener_pairs   = {}
  end

  #
  # Kills off the connection threads if there are any hanging around.
  #
  def cleanup_handler
    # Kill any remaining handle_connection threads that might
    # be hanging around
    stop_handler
    conn_threads.each { |thr|
      begin
        thr.kill
      rescue => e
        elog(e)
      end
    }
  end

  #
  # Starts a new connecting thread
  #
  def add_handler(opts={})

    # Merge the updated datastore values
    opts.each_pair do |k,v|
      datastore[k] = v
    end

    # Start a new handler
    start_handler
  end

  #
  # Starts monitoring for an outbound connection to become established.
  #
  def start_handler
    if datastore['EC2_ID'].blank?
      raise Msf::OptionValidateError.new({ 'EC2_ID' => "EC2_ID cannot be blank" })
    end

    # Maximum number of seconds to run the handler
    ctimeout = 150

    # Maximum number of seconds to await initial API response
    rtimeout = 5

    if (exploit_config and exploit_config['active_timeout'])
      ctimeout = exploit_config['active_timeout'].to_i
    end
    return if self.listener_pairs[datastore['EC2_ID']]
    self.listener_pairs[datastore['EC2_ID']] = true

    # Start a new handling thread
    self.listener_threads << framework.threads.spawn("BindAwsInstanceConnectHandler-#{datastore['EC2_ID']}", false) {
      instance_connect_client = nil

      print_status("Started #{human_name} handler against #{datastore['EC2_ID']}:#{datastore['REGION']}")

      stime = Time.now.to_i

      while (stime + ctimeout > Time.now.to_i)
        begin
          # Call API to start InstanceConnect session
          if start_instance_connect_session
            instance_connect_client = connect_ssh
          else
            raise Rex::ConnectionError.new('Cannot establish serial connection to ' + datastore['EC2_ID'])
          end
        rescue Aws::EC2InstanceConnect::Errors::SerialConsoleSessionLimitExceededException => e
          vprint_error("Too many active serial console sessions. It takes 30 seconds to tear down a session after you've disconnected from the serial console in order to allow a new session.")
        rescue Aws::Errors::ServiceError => e
          vprint_error(e.message)
        rescue Rex::ConnectionError => e
          vprint_error(e.message)
        rescue StandardError => e
          vprint_error(e.message)
          elog("Exception caught in InstanceConnect handler: #{$!.class} #{$!}", error: e)
          break
        end
        break if instance_connect_client

        # Wait a second before trying again
        Rex::ThreadSafe.sleep(0.5)
      end

      # Valid client connection?
      if (instance_connect_client)
        # Increment the has connection counter
        self.pending_connections += 1

        # Timeout and datastore options need to be passed through to the client
        opts = {
          :datastore       => datastore,
          :expiration      => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout    => datastore['SessionCommunicationTimeout'].to_i,
          :retry_total     => datastore['SessionRetryTotal'].to_i,
          :retry_wait      => datastore['SessionRetryWait'].to_i,
          :serial_username => datastore['USERNAME'],
          :serial_password => datastore['PASSWORD']
        }

        self.conn_threads << framework.threads.spawn("BindAwsInstanceConnectHandlerSession", false, instance_connect_client, opts) { |ssh, opts_copy|
          begin
            self.listener_pairs[datastore['EC2_ID']] = ssh
            handle_connection(ssh, opts_copy)
          rescue => e
            elog('Exception raised from BindAwsInstanceConnect.handle_connection', error: e)
          end
        }
      else
        wlog("No connection received before the handler completed")
      end
    }
  end

  # A URI describing what the payload is configured to use for transport
  def payload_uri
    "serial+ssh://#{datastore['EC2_ID']}:#{INSTANCE_PORT}"
  end

  def comm_string
    if self.listener_pairs[datastore['EC2_ID']].nil?
      "(setting up)"
    else
      "(via #{ssh_url})"
    end
  end

  def stop_handler
    # Stop the listener threads
    self.listener_threads.each do |t|
      t.kill
    end
    self.listener_threads = []
    self.listener_pairs = {}
  end

private

  # Any non-zero value currently triggers an exception but it looks like it may be configurable in the future.
  INSTANCE_PORT = 0

  #
  # Handles key consumption or generation as appropriate for the session
  #
  def ssh_key
    @ssh_key ||= if datastore['PRIVATE_KEY']
      Net::SSH::KeyFactory.load_data_private_key(
        File.read(datastore['PRIVATE_KEY']), datastore['KEY_PASS'], false
      )
    else
      Net::SSH::KeyFactory.load_data_private_key(
        OpenSSL::PKey::RSA.generate(2048).to_pem, nil, false
      )
    end
  end

  #
  # Produces appropriate SSH public key string from key materiel
  #
  def pub_key
    key_str = ssh_key.public_key.ssh_type
    key_str << ' '
    key_str << Rex::Text.encode_base64(ssh_key.public_key.to_blob)
    return key_str
  end

  #
  # Generates the SSH connection host for the SSH socket
  #
  def ssh_hostname(tld = '.aws')
    'serial-console.ec2-instance-connect.'+ datastore['REGION'] + tld
  end

  #
  # Generates the SSH username for the SSH socket
  #
  def ssh_user
    datastore['INSTANCE_USER'] || "#{datastore['EC2_ID']}.port#{INSTANCE_PORT}"
  end

  #
  # Convenience method for testing
  #
  def ssh_url
    ssh_user + '@' + ssh_hostname
  end

  #
  # Initiates SSH connection to AWS proxy - override this in modules
  #
  def connect_ssh
    ssh_options = {
      non_interactive: true,
      config: false,
      use_agent: false,
      verify_host_key: :never,
      append_all_supported_algorithms: true,
      check_host_ip: false,
      proxy: Rex::Socket::SSHFactory.new(framework, self, datastore['Proxies']),
      auth_methods: ['publickey'],
      key_data: [ssh_key.to_s],
      port: datastore['RPORT'] || 22
    }
    opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']
    ::Timeout.timeout(datastore['WfsTimeout']) do
      return Net::SSH.start(Rex::Socket.resolv_to_dotted(ssh_hostname), ssh_user, ssh_options)
    end
  end

  #
  # Starts an InstanceConnect session
  #
  def start_instance_connect_session
    # Configure AWS credentials
    credentials = if datastore['ACCESS_KEY_ID'] and datastore['SECRET_ACCESS_KEY']
      ::Aws::Credentials.new(datastore['ACCESS_KEY_ID'], datastore['SECRET_ACCESS_KEY'])
    else
      nil
    end
    # Attempt to assume role from current context
    credentials = if datastore['ROLE_ARN'] and datastore['ROLE_SID']
      ::Aws::AssumeRoleCredentials.new(
        client: ::Aws::STS::Client.new(
          region: datastore['REGION'],
          credentials: credentials
        ),
        role_arn: datastore['ROLE_ARN'],
        role_session_name: datastore['ROLE_SID']
      )
    else
      credentials
    end

    client = ::Aws::EC2InstanceConnect::Client.new(
      region: datastore['REGION'],
      credentials: credentials
    )
    session_params = {
      instance_id: datastore['EC2_ID'],
      serial_port: INSTANCE_PORT,
      ssh_public_key: pub_key
    }
    session_params[:instance_os_user] = datastore['INSTANCE_USER'] if datastore['INSTANCE_USER']

    # There are two methods for initiating a session, one with user-name, one without
    resp = if datastore['INSTANCE_USER']
      client.send_ssh_public_key(session_params)
    else
      client.send_serial_console_ssh_public_key(session_params)
    end
    return resp.success
  end

  def create_session(ssh, opts = {})
    s = Msf::Sessions::AwsInstanceConnectCommandShellBind.new(ssh, opts)
    # Pass along the framework context
    s.framework = framework

    # Associate this system with the original exploit
    # and any relevant information
    s.set_from_exploit(assoc_exploit) if assoc_exploit

    # If the session is valid, register it with the framework and
    # notify any waiters we may have.
    if s
      register_session(s)
    end

    return s
  end

protected

  attr_accessor :conn_threads # :nodoc:
  attr_accessor :listener_threads # :nodoc:
  attr_accessor :listener_pairs # :nodoc:


  module AwsInstanceConnectSessionChannelExt
    attr_accessor :localinfo
    attr_accessor :peerinfo
  end

end
end
end
