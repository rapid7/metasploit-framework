# -*- coding: binary -*-
require 'msf/core/modules/external'
require 'msf/core/modules/external/message'
require 'open3'

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
      n = receive_notification
      if n && n['params']
        n['params']
      else
        close_ios
        self.running = false
        n['response'] if n
      end
    end
  end

  def initialize(module_path)
    self.env = {}
    self.running = false
    self.path = module_path
  end

  protected

  attr_writer :path, :running
  attr_accessor :env, :ios

  def describe
    resp = send_receive(Msf::Modules::External::Message.new(:describe))
    close_ios
    resp['response']
  end

  # XXX TODO non-blocking writes, check write lengths, non-blocking JSON parse loop read

  def send_receive(message)
    send(message)
    read_json(message.id, self.ios[1])
  end

  def send(message)
    input, output, status = ::Open3.popen3(env, [self.path, self.path])
    self.ios = [input, output, status]
    case Rex::ThreadSafe.select(nil, [input], nil, 0.1)
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
    input, output, status = self.ios
    case Rex::ThreadSafe.select([output], nil, nil, 10)
    when nil
      nil
    when [[output], [], []]
      read_json(nil, output)
    end
  end

  def write_message(fd, json)
    fd.write(json)
  end

  def read_json(id, fd)
    begin
      resp = fd.readpartial(10_000)
      JSON.parse(resp)
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
