# -*- coding: binary -*-
module Msf
module Ui
module Web

module Comm

  class Channel
    def initialize
      @id = Comm.next_channel_id
    end

    def read
      nil
    end

    attr_accessor :id
  end

  class SessionChannel < Channel
    def initialize(session_id, pipe)
      super()

      @sid  = session_id
      @pipe = pipe

      @pipe.create_subscriber(channel.id)
    end

    def close
      @pipe.remove_subscriber(channel.id)
    end

    def write_input(msg)
      @pipe.write_input(msg)
    end

    def read
      @pipe.read_subscriber(channel.id)
    end
  end

  class SessionEventSubscriber
    include Msf::SessionEvent

    def on_session_open(session)
      pipe = Comm.create_session_pipe(session)

      session.init_ui(pipe, pipe)
    end
  end

  @@framework     = nil
  @@channels      = {}
  @@channel_id    = 0
  @@read_event    = Rex::Sync::Event.new(false, false)
  @@session_pipes = {}

  def self.setup(framework)
    @framework = framework

    framework.events.add_session_subscriber(SessionEventSubscriber.new)
  end

  def self.wakeup
    @read_event.set
  end

  def self.next_channel_id
    @channel_id += 1
  end

  def self.create_channel(client, request)
    create_session_channel(client.qstring['sid'].to_i)
  end

  def self.create_session_channel(session_id)
    channel = SessionChannel.new(session_id, @session_pipes[session_id])

    @channels[channel.id] = channel

    channel
  end

  def self.create_session_pipe(session)
    pipe = Rex::IO::BidirectionalPipe.new

    @session_pipes[session.id] = pipe

    pipe
  end

  def self.write_channel(client, request)
    channel_id = request.qstring['channel_id']
    data       = request.qstring['data']
    channel    = @channels[channel_id]

    if channel.nil? == false
      channel.write_input(data)
    end
  end

  def self.read_channels(client, request)
    dlog("read_channels: waiting for event")

    # Wait to see if there's any data available on channels.  If there
    # isn't, then we send a response immediately.  Otherwise, we check
    # to see if any of the requested channels were ones that we're
    # interested in.
    begin
      @@read_event.wait(15)
    rescue Timeout::Error
      client.send_response(Rex::Proto::Http::Response::OK.new)
      return
    end

    @@read_event.reset

    channels = request.qstring['channels']

    if channels.kind_of?(Array) == false
      channels = [channels]
    end

    # Walk each channel, checking to see if there is any read data.  If
    # there is, then we'll include it in the response body.
    body = '<channeldatum>'

    channels.each { |cid|
      channel = @channels[cid]

      next if channel.nil?

      buf = channel.read

      next if buf.nil?

      body += "<channeldata id=\"#{channel.id}\">#{Base64.encode64(buf)}</channeldata>"
    }

    body = '</channeldatum>'

    # Create and send the response
    response = Rex::Proto::Http::Response::OK.new
    response.body = body

    client.send_response(response)
  end

end

end
end
end

