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
    if self.running || !self.messages.empty?
      m = receive_notification
      if m.nil?
        close_ios
        self.messages.close
        self.running = false
      end

      return m
    end
  end

  def initialize(module_path)
    self.env = {}
    self.running = false
    self.path = module_path
    self.cmd = [[self.path, self.path]]
    self.messages = Queue.new
    self.buf = ''
  end

  protected

  attr_writer :path, :running
  attr_accessor :cmd, :env, :ios, :buf, :messages, :wait_thread

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
    input, output, err, status = ::Open3.popen3(self.env, *self.cmd)
    self.ios = [input, output, err]
    self.wait_thread = status
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
    _, out, err = self.ios
    message = ''

    # Multiple messages can come over the wire all at once, and since yajl
    # doesn't play nice with windows, we have to emulate a state machine to
    # read just enough off the wire to get one request at a time. Since
    # Windows cannot do a nonblocking read on a pipe, we are forced to do a
    # whole lot of `select` syscalls and keep a buffer ourselves :(
    begin
      loop do
        # This is so we don't end up calling JSON.parse on every char and
        # catch an exception. Windows can't do nonblock on pipes, so we
        # still have to do the select if we are not at the end of object
        # and don't have any buffer left
        parts = self.buf.split '}', 2
        if parts.length == 2 # [part, rest]
          message << parts[0] << '}'
          self.buf = parts[1]
          break
        elsif parts.length == 1 # [part]
          if self.buf[-1] == '}'
            message << parts[0] << '}'
            self.buf = ''
            break
          else
            message << parts[0]
            self.buf = ''
          end
        end

        # We would call Rex::Threadsafe directly, but that would require Rex for standalone use
        res = select([out, err], nil, nil, timeout)
        if res == nil
          # This is what we would have gotten without Rex and what `readpartial` can also raise
          raise EOFError.new
        else
          fds = res[0]
          # Preferentially drain and log stderr, EOF counts as activity, but
          # stdout might have some buffered data left, so carry on
          if fds.include?(err) && !err.eof?
            errbuf = err.readpartial(4096)
            elog "Unexpected output running #{self.path}:\n#{errbuf}"
          end
          if fds.include? out
            self.buf << out.readpartial(4096)
          end
        end
      end

      m = Msf::Modules::External::Message.from_module(JSON.parse(message))
      if filter_id && m.id != filter_id
        # We are filtering for a response to a particular message, but we got
        # something else, store the message and try again
        self.messages.push m
        recv(filter_id, timeout)
      else
        # Either we weren't filtering, or we got what we were looking for
        m
      end
    rescue JSON::ParserError
      # Probably an incomplete response, but no way to really tell. Keep trying
      # until EOF
      retry
    rescue EOFError => e
      nil
    end
  end

  def close_ios
    self.ios.each {|fd| fd.close rescue nil} # Yeah, yeah. I know.
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

class Msf::Modules::External::RbBridge < Msf::Modules::External::Bridge
  def self.applies?(module_name)
    module_name.match? /\.rb$/
  end

  def initialize(module_path)
    super

    ruby_path = File.expand_path('../ruby', __FILE__)
    self.cmd = [[Gem.ruby, 'ruby'], "-I#{ruby_path}", self.path]
  end
end

class Msf::Modules::External::Bridge

  LOADERS = [
    Msf::Modules::External::PyBridge,
    Msf::Modules::External::RbBridge,
    Msf::Modules::External::Bridge
  ]

  def self.open(module_path)
    LOADERS.each do |klass|
      return klass.new module_path if klass.applies? module_path
    end

    nil
  end
end
