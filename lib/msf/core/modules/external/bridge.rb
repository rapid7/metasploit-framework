# -*- coding: binary -*-
require 'msf/core/modules/external'
require 'msf/core/modules/external/message'
require 'open3'
require 'json'

class Msf::Modules::External::Bridge

  attr_reader :path, :running

  def self.applies?(module_name)
    File::executable? module_name
  end

  def meta
    @meta ||= describe
  end

  def run(datastore)
    unless self.running
      m = Msf::Modules::External::Message.new(:run)
      m.params = datastore.dup
      send(m)
      self.running = true
    end
  end

  def get_status
    if self.running
      m = receive_notification
      if m.nil?
        close_ios
        self.running = false
      end

      return m
    end
  end

  def initialize(module_path)
    self.env = {}
    self.running = false
    self.path = module_path
    self.cmd = [self.path, self.path]
    self.messages = Queue.new
  end

  protected

  attr_writer :path, :running
  attr_accessor :cmd, :env, :ios, :messages

  def describe
    resp = send_receive(Msf::Modules::External::Message.new(:describe))
    close_ios
    resp.params
  end

  # XXX TODO non-blocking writes, check write lengths

  def send_receive(message)
    send(message)
    recv(message.id)
  end

  def send(message)
    input, output, status = ::Open3.popen3(self.env, self.cmd)
    self.ios = [input, output, status]
    # We would call Rex::Threadsafe directly, but that would require rex for standalone use
    case select(nil, [input], nil, 0.1)
    when nil
      raise "Cannot run module #{self.path}"
    when [[], [input], []]
      m = message.to_json
      write_message(input, m)
    else
      raise "Error running module #{self.path}"
    end
  end

  def receive_notification
    if self.messages.empty?
      recv
    else
      self.messages.pop
    end
  end

  def write_message(fd, json)
    fd.write(json)
  end

  def recv(filter_id=nil, timeout=600)
    _, fd, _ = self.ios

    # Multiple messages can come over the wire all at once, and since yajl
    # doesn't play nice with windows, we have to emulate a state machine to
    # read just enough off the wire to get one request at a time. Since
    # Windows cannot do a nonblocking read on a pipe, we are forced to do a
    # whole lot of `select` syscalls :(
    buf = ""
    begin
      loop do
        # We would call Rex::Threadsafe directly, but that would require Rex for standalone use
        case select([fd], nil, nil, timeout)
        when nil
          # This is what we would have gotten without Rex and what `readpartial` can also raise
          raise EOFError.new
        when [[fd], [], []]
          c = fd.readpartial(1)
          buf << c

          # This is so we don't end up calling JSON.parse on every char and
          # having to catch an exception. Windows can't do nonblock on pipes,
          # so we still have to do the select each time.
          break if c == '}'
        end
      end

      m = Msf::Modules::External::Message.from_module(JSON.parse(buf))
      if filter_id && m.id != filter_id
        # We are filtering for a response to a particular message, but we got
        # something else, store the message and try again
        self.messages.push m
        read_json(filter_id, timeout)
      else
        # Either we weren't filtering, or we got what we were looking for
        m
      end
    rescue JSON::ParserError
      # Probably an incomplete response, but no way to really tell
      retry
    rescue EOFError => e
      {}
    end
  end

  def close_ios
    input, output, status = self.ios
    [input, output].each {|fd| fd.close rescue nil} # Yeah, yeah. I know.
  end
end

class Msf::Modules::External::PyBridge < Msf::Modules::External::Bridge
  def self.applies?(module_name)
    module_name.match? /\.py$/
  end

  def initialize(module_path)
    super
    pythonpath = ENV['PYTHONPATH'] || ''
    self.env = self.env.merge({ 'PYTHONPATH' => pythonpath + File::PATH_SEPARATOR + File.expand_path('../python', __FILE__) })
  end
end

class Msf::Modules::External::Bridge

  LOADERS = [
    Msf::Modules::External::PyBridge,
    Msf::Modules::External::Bridge
  ]

  def self.open(module_path)
    LOADERS.each do |klass|
      return klass.new module_path if klass.applies? module_path
    end

    nil
  end
end
