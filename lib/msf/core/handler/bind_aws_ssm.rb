# -*- coding: binary -*-
module Msf
module Handler

require 'aws-sdk-ssm'
###
#
# This module implements the AWS SSM handler.  This means that
# it will attempt to connect to a remote host through the AWS SSM pipe for
# a period of time (typically the duration of an exploit) to see if a the
# agent has started listening.
#
###
module BindAwsSsm
  include Rex::Proto::Http::WebSocket::AmazonSsm
  include Msf::Handler
  ###
  #
  # This module implements SSM R/W abstraction to mimic Rex::IO::Stream interfaces
  # These methods are not fully synchronized/thread-safe as the req/resp chain is
  # itself async and rely on a cursor to obtain responses when they are ready from
  # the SSM API.
  #
  ###

  class AwsSsmSessionChannel

    include Rex::IO::StreamAbstraction

    def initialize(framework, ssmclient, peer_info)
      @framework = framework
      @peer_info = peer_info
      @ssmclient = ssmclient
      @cursor    = nil
      @cmd_doc   = peer_info['CommandDocument']

      initialize_abstraction

      self.lsock.extend(AwsSsmSessionChannelExt)
      # self.lsock.peerinfo  = peer_info['ComputerName'] + ':0'
      self.lsock.peerinfo  = peer_info['IpAddress'] + ':0'
      # Fudge the portspec since each client request is actually a new connection w/ a new source port, for now
      self.lsock.localinfo = Rex::Socket.source_address(@ssmclient.config.endpoint.to_s.sub('https://', '')) + ':0'

      monitor_shell_stdout
    end

    #
    # Funnel data from the shell's stdout to +rsock+
    #
    # +StreamAbstraction#monitor_rsock+ will deal with getting data from
    # the client (user input).  From there, it calls our write() below,
    # funneling the data to the shell's stdin on the other side.
    #
    def monitor_shell_stdout
      @monitor_thread = @framework.threads.spawn('AwsSsmSessionHandlerMonitor', false) {
        begin
          while true
            Rex::ThreadSafe.sleep(0.5) while @cursor.nil?
            # Handle data from the API and write to the client
            buf = ssm_read
            break if buf.nil?
            rsock.put(buf)
          end
        rescue ::Exception => e
          ilog("AwsSsmSession monitor thread raised #{e.class}: #{e}")
        end
      }
    end

    # Find command response on cursor and return to caller - doesn't respect length arg, yet
    def ssm_read(length = nil, opts = {})
      maxw = opts[:timeout] ? opts[:timeout] : 30
      start = Time.now
      resp = @ssmclient.list_command_invocations(command_id: @cursor, instance_id: @peer_info['InstanceId'], details: true)
      while (resp.command_invocations.empty? or resp.command_invocations[0].status == 'InProgress') and
        (Time.now - start).to_i.abs < maxw do
        Rex::ThreadSafe.sleep(1)
        resp = @ssmclient.list_command_invocations(command_id: @cursor, instance_id: @peer_info['InstanceId'], details: true)
      end
      # SSM script invocation states are: InProgress, Success, TimedOut, Cancelled, Failed
      if resp.command_invocations[0].status == 'Success' or resp.command_invocations[0].status == 'Failed'
        # The big limitation: SSM command outputs are only 2500 chars max, otherwise you have to write to S3 and read from there
        output = resp.command_invocations.map {|c| c.command_plugins.map {|p| p.output}.join}.join
        @cursor = nil
        return output
      else
        @cursor = nil
        ilog("AwsSsmSession error #{resp}")
        raise resp
      end
      nil
    end

    def write(buf, opts = {})
      resp = @ssmclient.send_command(
        document_name: @cmd_doc,
        instance_ids: [@peer_info['InstanceId']],
        parameters: { commands: [buf] }
      )
      if resp.command.error_count == 0
        @cursor = resp.command.command_id
        return buf.length
      else
        @cursor = nil
        ilog("AwsSsmSession error #{resp}")
        raise resp
      end
    end

    #
    # Closes the stream abstraction and kills the monitor thread.
    #
    def close
      @monitor_thread.kill if (@monitor_thread)
      @monitor_thread = nil

      cleanup_abstraction
    end
  end
  #
  # Returns the handler specific string representation, in this case
  # 'bind_aws_ssm'.
  #
  def self.handler_type
    return 'bind_aws_ssm'
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
    'bind AWS SSM'
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
        OptString.new('ROLE_ARN', [false, 'AWS assumed role ARN', nil]),
        OptString.new('ROLE_SID', [false, 'AWS assumed role session ID', nil]),
      ], Msf::Handler::BindAwsSsm)

    register_advanced_options(
      [
        OptString.new('SSM_SESSION_DOC', [true, 'The SSM document to use for session requests', 'SSM-SessionManagerRunShell']),
        OptBool.new('SSM_KEEP_ALIVE', [false, 'Keep AWS SSM session alive with empty messages', true])
      ], Msf::Handler::BindAwsSsm)

    self.listener_threads = []
    self.conn_threads = []
    self.listener_pairs = {}
  end

  #
  # Kills off the connection threads if there are any hanging around.
  #
  def cleanup_handler
    # Kill any remaining handle_connection threads that might
    # be hanging around
    stop_handler

    conn_threads.each { |thr|
      thr.kill
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

    # Maximum number of seconds to run the handler
    ctimeout = 150

    # Maximum number of seconds to await initial API response
    rtimeout = 5

    if (exploit_config and exploit_config['active_timeout'])
      ctimeout = exploit_config['active_timeout'].to_i
    end

    # Ignore this if one of the requried options is missing
    return if datastore['EC2_ID'].blank?

    # Only try the same host/port combination once
    return if self.listener_pairs[datastore['EC2_ID']]
    self.listener_pairs[datastore['EC2_ID']] = true

    # Start a new handling thread
    self.listener_threads << framework.threads.spawn("BindAwsSsmHandler-#{datastore['EC2_ID']}", false) do
      ssm_client = nil

      print_status("Started #{human_name} handler against #{datastore['EC2_ID']}:#{datastore['REGION']}")

      stime = Time.now.to_i

      while (stime + ctimeout > Time.now.to_i)
        begin
          ssm_client, peer_info = get_ssm_session
        rescue Rex::ConnectionError => e
          vprint_error(e.message)
        rescue
          wlog("Exception caught in AWS SSM handler: #{$!.class} #{$!}")
          break
        end
        break if ssm_client

        # Wait a half-second before trying again
        Rex::ThreadSafe.sleep(0.5)
      end

      # Valid client connection?
      if ssm_client
        # Increment the has connection counter
        self.pending_connections += 1

        # Timeout and datastore options need to be passed through to the client
        opts = {
          datastore: datastore,
          expiration: datastore['SessionExpirationTimeout'].to_i,
          comm_timeout: datastore['SessionCommunicationTimeout'].to_i,
          retry_total: datastore['SessionRetryTotal'].to_i,
          retry_wait: datastore['SessionRetryWait'].to_i
        }

        self.conn_threads << framework.threads.spawn('BindAwsSsmHandlerSession', false, ssm_client, peer_info) do |client_copy, info_copy|
          begin
            session_params = {
              target: datastore['EC2_ID'],
              document_name: datastore['SSM_SESSION_DOC']
            }

            # Call API to start SSM session
            session_init = client_copy.start_session(session_params)
            # Create WebSocket from parameters
            ssm_sock = connect_ssm_ws(session_init)
            # Create Channel from WebSocket
            chan = ssm_sock.to_ssm_channel
            # Configure Channel
            chan._start_ssm_keepalive if datastore['SSM_KEEP_ALIVE']
            chan.params.comm = Rex::Socket::Comm::Local unless chan.params.comm
            chan.params.peerhost = peer_info['IpAddress']
            chan.params.peerport = 0
            chan.params.peerhostname = peer_info['ComputerName']
            chan.update_term_size
          rescue => e
            print_error("AWS SSM handler failed: #{e.message}")
            elog('Exception raised from BindAwsSsm', error: e)
            return
          end

          self.listener_pairs[datastore['EC2_ID']] = chan

          handle_connection(chan.lsock, { datastore: datastore, aws_ssm_host_info: peer_info })
        end
      else
        wlog('No connection received before the handler completed')
      end
    end
  end

  # A URI describing what the payload is configured to use for transport
  def payload_uri
    "ssm://#{datastore['EC2_ID']}:0"
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

  #
  # Starts an SSM session, verifying presence of target
  #
  def get_ssm_session
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

    client = ::Aws::SSM::Client.new(
      region: datastore['REGION'],
      credentials: credentials,
    )
    # Verify the connection params and availability of instance
    inv_params = { filters: [
      {
        key: 'AWS:InstanceInformation.InstanceId',
        values: [datastore['EC2_ID']],
        type: 'Equal',
      }
    ]}
    inventory = client.get_inventory(inv_params)
    # Extract peer info
    if inventory.entities[0] and inventory.entities[0].id == datastore['EC2_ID']
      peer_info = inventory.entities[0].data['AWS:InstanceInformation'].content[0]
    else
      raise 'AWS SSM target not found'
    end
    return [client, peer_info]
  end

  def create_session(ssm, opts = {})
    # If there is a parent payload, then use that in preference.
    s = Sessions::AwsSsmCommandShellBind.new(ssm, opts)
    # Pass along the framework context
    s.framework = framework

    # Associate this system with the original exploit
    # and any relevant information
    s.set_from_exploit(assoc_exploit)

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


  module AwsSsmSessionChannelExt
    attr_accessor :localinfo
    attr_accessor :peerinfo
  end

end
end
end
