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

      initialize_abstraction

      self.lsock.extend(AwsSsmSessionChannelExt)
      # self.lsock.peerinfo  = peer_info['ComputerName'] + ':0'
      self.lsock.peerinfo  = peer_info['IpAddress'] + ':0'
      # Fudge the portspec since each client request is actually a new connection w/ a new source port, for now
      self.lsock.localinfo = Rex::Socket.source_address(@ssmclient.config.endpoint.to_s.sub('https://','')) + ':0'

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
      @monitor_thread = @framework.threads.spawn("AwsSsmSessionHandlerMonitor", false) {
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
      while (resp.command_invocations.empty? or resp.command_invocations[0].status == "InProgress") and
        (Time.now - start).to_i.abs < maxw do
        Rex::ThreadSafe.sleep(1)
        resp = @ssmclient.list_command_invocations(command_id: @cursor, instance_id: @peer_info['InstanceId'], details: true)
      end
      # SSM script invocation states are: InProgress, Success, TimedOut, Cancelled, Failed
      if resp.command_invocations[0].status == "Success" or  resp.command_invocations[0].status == "Failed"
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
        document_name: 'AWS-RunShellScript',
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
  # 'bind_tcp'.
  #
  def self.handler_type
    return "bind_aws_ssm"
  end

  #
  # Returns the connection oriented general handler type, in this case bind.
  #
  def self.general_handler_type
    "bind"
  end

  # A string suitable for displaying to the user
  #
  # @return [String]
  def human_name
    "bind AWS SSM"
  end

  #
  # Initializes a bind handler and adds the options common to all bind
  # payloads, such as local port.
  #
  def initialize(info = {})
    super

    register_options(
      [
        OptString.new('AWS_EC2_ID', [true, 'The EC2 ID of the instance ', '']),
        OptString.new('AWS_REGION', [true, 'AWS region containing the instance', 'us-east-1']),
        OptString.new('AWS_AK', [false, 'AWS access key', nil]),
        OptString.new('AWS_SK', [false, 'AWS secret key', nil]),
        OptString.new('AWS_ROLE_ARN', [false, 'AWS assumed role ARN', nil]),
        OptString.new('AWS_ROLE_SID', [false, 'AWS assumed role session ID', nil]),
      ], Msf::Handler::BindAwsSsm)

    self.bind_thread = nil
    self.conn_thread = nil
  end

  #
  # Kills off the connection threads if there are any hanging around.
  #
  def cleanup_handler
    # Kill any remaining handle_connection threads that might
    # be hanging around
    stop_handler
    self.bind_thread = nil
    self.conn_thread = nil
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

    # Start a new handling thread
    self.bind_thread = framework.threads.spawn("BindAwsSsmHandler-#{datastore['AWS_EC2_ID']}", false) {
      client = nil

      print_status("Started #{human_name} handler against #{datastore['AWS_EC2_ID']}:#{datastore['AWS_REGION']}")

      if (datastore['AWS_EC2_ID'] == nil or datastore['AWS_EC2_ID'].strip.empty?)
        raise ArgumentError,
          "AWS_EC2_ID is not defined; SSM handler cannot function.",
          caller
      end

      stime = Time.now.to_i

      while (stime + ctimeout > Time.now.to_i)
        begin
          ssm_client, peer_info = get_ssm_session
        rescue Rex::ConnectionError => e
          vprint_error(e.message)
        rescue
          wlog("Exception caught in SSM handler: #{$!.class} #{$!}")
          break
        end
        break if ssm_client

        # Wait a second before trying again
        Rex::ThreadSafe.sleep(0.5)
      end

      # Valid client connection?
      if (ssm_client)
        # Increment the has connection counter
        self.pending_connections += 1

        # Timeout and datastore options need to be passed through to the client
        opts = {
          :datastore    => datastore,
          :expiration   => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout => datastore['SessionCommunicationTimeout'].to_i,
          :retry_total  => datastore['SessionRetryTotal'].to_i,
          :retry_wait   => datastore['SessionRetryWait'].to_i,
        }

        self.conn_thread = framework.threads.spawn("BindAwsSsmHandlerSession", false, ssm_client, peer_info) { |client_copy, info_copy|
          begin
            chan = get_ws_session(client_copy.start_session({
              target: datastore['AWS_EC2_ID'],
              document_name: 'SSM-SessionManagerRunShell'
            }))
          rescue Rex::Proto::Http::WebSocket::ConnectionError
            chan = AwsSsmSessionChannel.new(framework, client_copy, info_copy)
          rescue => e
            elog('Exception raised from BindAwsSsm.handle_connection', error: e)
          end
          handle_connection(chan.lsock, { datastore: datastore })
        }
      else
        wlog("No connection received before the handler completed")
      end
    }
  end

  # A URI describing what the payload is configured to use for transport
  def payload_uri
    "ssm://#{datastore['AWS_EC2_ID']}:0"
  end

  def comm_string
    if bind_sock.nil?
      "(setting up)"
    else
      via_string(bind_sock.client) if bind_sock.respond_to?(:client)
    end
  end

  def stop_handler
    if (self.conn_thread and self.conn_thread.alive? == true)
      self.bind_thread.kill
      self.bind_thread = nil
    end

    if (self.bind_thread and self.bind_thread.alive? == true)
      self.bind_thread.kill
      self.bind_thread = nil
    end
  end

private

  #
  # Starts an SSM session, verifying presence of target
  #
  def get_ssm_session
    # Configure AWS credentials
    credentials = if datastore['AWS_AK'] and datastore['AWS_SK']
      ::Aws::Credentials.new(datastore['AWS_AK'], datastore['AWS_SK'])
    else
      nil
    end
    credentials = if datastore['AWS_ROLE_ARN'] and datastore['AWS_ROLE_SID']
      ::Aws::AssumeRoleCredentials.new(
        client: ::Aws::STS::Client.new(
          region: datastore['AWS_REGION'],
          credentials: credentials
        ),
        role_arn: datastore['AWS_ROLE_ARN'],
        role_session_name: datastore['AWS_ROLE_SID']
      )
    else
      credentials
    end

    client = ::Aws::SSM::Client.new(
      region: datastore['AWS_REGION'],
      credentials: credentials,
    )
    # Verify the connection params and availability of instance
    inv_params = { filters: [
      {
        key: "AWS:InstanceInformation.InstanceId",
        values: [datastore['AWS_EC2_ID']],
        type: "Equal",
      }
    ]}
    inventory = client.get_inventory(inv_params)
    # Extract peer info
    if inventory.entities[0] and inventory.entities[0].id == datastore['AWS_EC2_ID']
      peer_info = inventory.entities[0].data['AWS:InstanceInformation'].content[0]
    else
      raise "SSM target not found"
    end
    return [client, peer_info]
  end

  #
  # Initiates a WebSocket session based on the params of SSM::Client#start_session
  #
  def get_ws_session(session_init, timeout = 20)
    ws_key = session_init.token_value
    ssm_id = session_init.session_id
    ws_url = URI.parse(session_init.stream_url)
    opts   = {}
    opts['vhost']   = ws_url.host
    opts['uri']     = ws_url.to_s.sub(/^.*#{ws_url.host}/,'')
    opts['headers'] = {
      'Connection'            => 'Upgrade',
      'Upgrade'               => 'WebSocket',
      'Sec-WebSocket-Version' => 13,
      'Sec-WebSocket-Key'     => ws_key
    }

    http_client = Rex::Proto::Http::Client.new(
      ws_url.host,
      443,
      {
        'Msf'        => framework,
        'MsfExploit' => self,
      },
      true
    )
    raise Rex::Proto::Http::WebSocket::ConnectionError.new if http_client.nil?

    req = http_client.request_raw(opts)
    res = http_client.send_recv(req, timeout)
    unless res&.code == 101
      disconnect
      raise Rex::Proto::Http::WebSocket::ConnectionError.new(http_response: res)
    end

    # see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Accept
    accept_ws_key = Rex::Text.encode_base64(OpenSSL::Digest::SHA1.digest(ws_key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'))
    unless res.headers['Sec-WebSocket-Accept'] == accept_ws_key
      disconnect
      raise Rex::Proto::Http::WebSocket::ConnectionError.new(msg: 'Invalid Sec-WebSocket-Accept header', http_response: res)
    end

    socket = http_client.conn
    socket.extend(Rex::Proto::Http::WebSocket::Interface)
    # handshake
    # establish shell channel

    # hack-up a "graceful fail-down" in the caller
    raise Rex::Proto::Http::WebSocket::ConnectionError.new(msg: 'WebSocket sesssions are not yet implemented')
  end
protected

  attr_accessor :bind_thread # :nodoc:
  attr_accessor :conn_thread # :nodoc:


  module AwsSsmSessionChannelExt
    attr_accessor :localinfo
    attr_accessor :peerinfo
  end

end
end
end