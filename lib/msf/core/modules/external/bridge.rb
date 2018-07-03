# -*- coding: binary -*-
require 'open3'
require 'json'

module Msf::Modules
  class External
    class Bridge

      attr_reader :path, :running, :messages, :exit_status

      def self.applies?(module_name)
        File::executable? module_name
      end

      def exec(req)
        unless self.running
          self.running = true
          send(req)
          self.read_thread = threadme do
            begin
              while self.running && m = next_message
                self.messages.push m
              end
            ensure
              cleanup
            end
          end

          self
        end
      end

      def close
        self.running = false
        self.read_thread.join

        self
      end

      def success?
        self.exit_status && self.exit_status.success?
      end

      def initialize(module_path, framework: nil)
        self.env = {}
        self.running = false
        self.path = module_path
        self.cmd = [[self.path, self.path]]
        self.messages = Queue.new
        self.buf = ''
        self.framework = framework
      end

      protected

      attr_writer :path, :running, :messages, :exit_status
      attr_accessor :cmd, :env, :ios, :buf, :read_thread, :wait_thread, :framework

      # XXX TODO non-blocking writes, check write lengths

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

      def write_message(fd, json)
        fd.write(json)
      end

      def next_message(timeout=600)
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
              message << parts[0]
              self.buf = ''
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
                if self.framework
                  elog "Unexpected output running #{self.path}:\n#{errbuf}"
                else
                  $stderr.puts errbuf
                end
              end
              if fds.include? out
                self.buf << out.readpartial(4096)
              end
            end
          end

          Message.from_module(JSON.parse(message))
        rescue JSON::ParserError
          # Probably an incomplete response, but no way to really tell. Keep trying
          # until EOF
          retry
        rescue EOFError => e
          self.running = false
        end
      end

      def harvest_process
        if self.wait_thread.join(10)
          self.exit_status = self.wait_thread.value
        elsif Process.kill('TERM', self.wait_thread.pid) && self.wait_thread.join(10)
          self.exit_status = self.wait_thread.value
        else
          Procoess.kill('KILL', self.wait_thread.pid)
          self.exit_status = self.wait_thread.value
        end
      end

      def cleanup
        self.running = false
        self.messages.close
        harvest_process
        self.ios.each {|fd| fd.close rescue nil} # Yeah, yeah. I know.
      end

      def threadme(&block)
        if self.framework
          # Leak as few connections as possible
          self.framework.threads.spawn("External Module #{self.path}", false, &block)
        else
          ::Thread.new &block
        end
      end
    end
  end
end

class Msf::Modules::External::PyBridge < Msf::Modules::External::Bridge
  def self.applies?(module_name)
    module_name.match? /\.py$/
  end

  def initialize(module_path, framework: nil)
    super
    pythonpath = ENV['PYTHONPATH'] || ''
    self.env = self.env.merge({ 'PYTHONPATH' => pythonpath + File::PATH_SEPARATOR + File.expand_path('../python', __FILE__) })
  end
end

class Msf::Modules::External::RbBridge < Msf::Modules::External::Bridge
  def self.applies?(module_name)
    module_name.match? /\.rb$/
  end

  def initialize(module_path, framework: nil)
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

  def self.open(module_path, framework: nil)
    LOADERS.each do |klass|
      return klass.new module_path, framework: framework if klass.applies? module_path
    end

    nil
  end
end
