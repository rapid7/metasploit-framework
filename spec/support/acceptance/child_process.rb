require 'stringio'
require 'open3'
require 'English'
require 'tempfile'
require 'fileutils'
require 'timeout'
require 'shellwords'

module Acceptance
  class ChildProcessError < ::StandardError
  end

  class ChildProcessTimeoutError < ::StandardError
  end

  class ChildProcessRecvError < ::StandardError
  end

  # A wrapper around ::Open3.popen2e - allows creating a process, writing to stdin, and reading the process output
  # All of the data is stored for future retrieval/appending to test output
  class ChildProcess
    def initialize
      super

      @default_timeout = ENV['CI'] ? 120 : 40
      @debug = false
      @env ||= {}
      @cmd ||= []
      @options ||= {}

      @stdin = nil
      @stdout_and_stderr = nil
      @wait_thread = nil

      @buffer = StringIO.new
      @all_data = StringIO.new
    end

    # @return [String] All data that was read from stdout/stderr of the running process
    def all_data
      @all_data.string
    end

    # Runs the process
    # @return [nil]
    def run
      self.stdin, self.stdout_and_stderr, self.wait_thread = ::Open3.popen2e(
        @env,
        *@cmd,
        **@options
      )

      stdin.sync = true
      stdout_and_stderr.sync = true

      nil
    rescue StandardError => e
      warn "popen failure #{e}"
      raise
    end

    # @return [String] A line of input
    def recvline(timeout: @default_timeout)
      recvuntil($INPUT_RECORD_SEPARATOR, timeout: timeout)
    end

    alias readline recvline

    # @param [String|Regexp] delim
    def recvuntil(delim, timeout: @default_timeout, drop_delim: false)
      buffer = ''
      result = nil

      with_countdown(timeout) do |countdown|
        while alive? && !countdown.elapsed?
          data_chunk = recv(timeout: [countdown.remaining_time, 1].min)
          if !data_chunk
            next
          end

          buffer += data_chunk
          has_delimiter = delim.is_a?(Regexp) ? buffer.match?(delim) : buffer.include?(delim)
          next unless has_delimiter

          result, matched_delim, remaining = buffer.partition(delim)
          unless drop_delim
            result += matched_delim
          end
          unrecv(remaining)
          # Reset the temporary buffer to avoid the `ensure` mechanism unrecv'ing the buffer unintentionally
          buffer = ''

          return result
        end
      ensure
        unrecv(buffer)
      end

      result
    rescue ChildProcessTimeoutError
      raise ChildProcessRecvError, "Failed #{__method__}: Did not match #{delim.inspect}, process was alive?=#{alive?.inspect}, remaining buffer: #{self.buffer.string[self.buffer.pos..].inspect}"
    end

    # @return [String] Recv until additional reads would cause a block, or eof is reached, or a maximum timeout is reached
    def recv_available(timeout: @default_timeout)
      result = ''
      finished_reading = false

      with_countdown(timeout) do
        until finished_reading do
          data_chunk = recv(timeout: 0, wait_readable: false)
          if !data_chunk
            finished_reading = true
            next
          end

          result += data_chunk
        end
      end

      result
    rescue EOFError, ChildProcessTimeoutError
      result
    end

    # @param [String] data The string of bytes to put back onto the buffer; Future buffered reads will return these bytes first
    def unrecv(data)
      data.bytes.reverse.each { |b| buffer.ungetbyte(b) }
    end

    # @param [Integer] length Reads length bytes from the I/O stream
    # @param [Integer] timeout The timeout in seconds
    # @param [TrueClass] wait_readable True if blocking, false otherwise
    def recv(length = 4096, timeout: @default_timeout, wait_readable: true)
      buffer_result = buffer.read(length)
      return buffer_result if buffer_result

      retry_count = 0

      # Eagerly read, and if we fail - await a response within the given timeout period
      result = nil
      begin
        result = stdout_and_stderr.read_nonblock(length)
        unless result.nil?
          log("[read] #{result}")
          @all_data.write(result)
        end
      rescue IO::WaitReadable
        if wait_readable
          IO.select([stdout_and_stderr], nil, nil, timeout)
          retry_count += 1
          retry if retry_count == 1
        end
      end

      result
    end

    # @param [String] data Write the data to the tdin of the running process
    def write(data)
      log("[write] #{data}")
      @all_data.write(data)
      stdin.write(data)
      stdin.flush
    end

    # @param [String] s Send line of data to the stdin of the running process
    def sendline(s)
      write("#{s}#{$INPUT_RECORD_SEPARATOR}")
    end

    # @return [TrueClass, FalseClass] True if the running process is alive, false otherwise
    def alive?
      wait_thread.alive?
    end

    # Interact with the current process, forwarding the current stdin to the console's stdin,
    # and writing the console's output to stdout. Doesn't support using PTY/raw mode.
    def interact
      $stderr.puts
      $stderr.puts '[*] Opened interactive mode - enter "!next" to continue, or "!exit" to stop entirely. !pry for an interactive pry'
      $stderr.puts

      without_debugging do
        while alive?
          ready = IO.select([stdout_and_stderr, $stdin], [], [], 10)

          next unless ready

          reads, = ready

          reads.to_a.each do |read|
            case read
            when $stdin
              input = $stdin.gets
              if input.chomp == '!continue'
                return
              elsif input.chomp == '!exit'
                exit
              elsif input.chomp == '!pry'
                require 'pry-byebug'; binding.pry
              end

              write(input)
            when stdout_and_stderr
              available_bytes = recv
              $stdout.write(available_bytes)
              $stdout.flush
            end
          end
        end
      end
    end

    def close
      begin
        Process.kill('KILL', wait_thread.pid) if wait_thread.pid
      rescue StandardError => e
        warn "error #{e} for #{@cmd}, pid #{wait_thread.pid}"
      end
      stdin.close if stdin
      stdout_and_stderr.close if stdout_and_stderr
    end

    # @return [IO] the stdin for the child process which can be written to
    attr_reader :stdin
    # @return [IO] the stdout and stderr for the child process which can be read from
    attr_reader :stdout_and_stderr
    # @return [Process::Waiter] the waiter thread for the current process
    attr_reader :wait_thread

    # @return [String] The cmd that was used to execute the current process
    attr_reader :cmd

    private

    # @return [StringIO] the buffer for any data which was read from stdout/stderr which was read, but not consumed
    attr_reader :buffer
    # @return [IO] the stdin of the running process
    attr_writer :stdin
    # @return [IO] the stdout and stderr of the running process
    attr_writer :stdout_and_stderr
    # @return [Process::Waiter] The process wait thread which tracks if the process is alive, its pid, return value, etc.
    attr_writer :wait_thread

    # @param [String] s Log to stderr
    def log(s)
      return unless @debug

      $stderr.puts s
    end

    def without_debugging
      previous_debug_value = @debug
      @debug = false
      yield
    ensure
      @debug = previous_debug_value
    end

    # Yields a timer object that can be used to request the remaining time available
    def with_countdown(timeout)
      countdown = Acceptance::Countdown.new(timeout)
      # It is the caller's responsibility to honor the required countdown limits,
      # but let's wrap the full operation in an explicit for worse case scenario,
      # which may leave object state in a non-determinant state depending on the call
      ::Timeout.timeout(timeout * 1.5) do
        yield countdown
      end
      if countdown.elapsed?
        raise ChildProcessTimeoutError
      end
    rescue ::Timeout::Error
      raise ChildProcessTimeoutError
    end
  end

  # Internally generates a temporary file with Dir::Tmpname instead of a ::Tempfile instance, otherwise windows won't allow the file to be executed
  # at the same time as the current Ruby process having an open handle to the temporary file
  class TempChildProcessFile
    def initialize(basename, extension)
      @file_path = Dir::Tmpname.create([basename, extension]) do |_path, _n, _opts, _origdir|
        # noop
      end

      ObjectSpace.define_finalizer(self, self.class.finalizer_proc_for(@file_path))
    end

    def path
      @file_path
    end

    def to_s
      path
    end

    def inspect
      "#<#{self.class} #{self.path}>"
    end

    def self.finalizer_proc_for(path)
      proc { File.delete(path) if File.exist?(path) }
    end
  end

  ###
  # Stores the data for a payload, including the options used to generate the payload,
  ###
  class Payload
    attr_reader :name, :execute_cmd, :generate_options, :datastore

    def initialize(options)
      @name = options.fetch(:name)
      @execute_cmd = options.fetch(:execute_cmd)
      @generate_options = options.fetch(:generate_options)
      @datastore = options.fetch(:datastore)
      @executable = options.fetch(:executable, false)

      basename = "#{File.basename(__FILE__)}_#{name}".gsub(/[^a-zA-Z]/, '-')
      extension = options.fetch(:extension, '')

      @file_path = TempChildProcessFile.new(basename, extension)
    end

    # @return [TrueClass, FalseClass] True if the payload needs marked as executable before being executed
    def executable?
      @executable
    end

    # @return [String] The path to the payload on disk
    def path
      @file_path.path
    end

    # @return [Integer] The size of the payload on disk. May be 0 when the payload doesn't exist,
    #   or a smaller size than expected if the payload is not fully generated by msfconsole yet.
    def size
      File.size(path)
    rescue StandardError => _e
      0
    end

    def [](k)
      options[k]
    end

    # @return [Array<String>] The command which can be used to execute this payload. For instance ["python3", "/tmp/path.py"]
    def execute_command
      @execute_cmd.map do |val|
        val.gsub('${payload_path}', path)
      end
    end

    # @param [Hash] default_global_datastore
    # @return [String] The setg commands for setting the global datastore
    def setg_commands(default_global_datastore: {})
      commands = []
      # Ensure the global framework datastore is always clear
      commands << "irb -e '(self.respond_to?(:framework) ? framework : self).datastore.user_defined.clear'"
      # Call setg
      global_datastore = default_global_datastore.merge(@datastore[:global])
      global_datastore.each do |key, value|
        commands << "setg #{key} #{value}"
      end
      commands.join("\n")
    end

    # @param [Hash] default_module_datastore
    # @return [String] The command which can be used on msfconsole to generate the payload
    def generate_command(default_module_datastore: {})
      module_datastore = default_module_datastore.merge(@datastore[:module])
      generate_options = @generate_options.map do |key, value|
        "#{key} #{value}"
      end
      module_options = module_datastore.map do |key, value|
        "#{key}=#{value}"
      end

      "generate -o #{path} #{generate_options.join(' ')} #{module_options.join(' ')}"
    end

    # @param [Hash] default_global_datastore
    # @param [Hash] default_module_datastore
    # @return [String] A human readable representation of the payload configuration object
    def as_readable_text(default_global_datastore: {}, default_module_datastore: {})
      <<~EOF
        ## Payload
        use #{name}

        ## Set global datastore
        #{setg_commands(default_global_datastore: default_global_datastore)}

        ## Generate command
        #{generate_command(default_module_datastore: default_module_datastore)}

        ## Create listener
        to_handler

        ## Execute command
        #{Shellwords.join(execute_command)}
      EOF
    end
  end

  class PayloadProcess
    # @return [Process::Waiter] the waiter thread for the current process
    attr_reader :wait_thread

    # @return [String] the executed command
    attr_reader :cmd

    # @return [String] the payload path on disk
    attr_reader :payload_path

    # @param [Array<String>] cmd The command which can be used to execute this payload. For instance ["python3", "/tmp/path.py"]
    # @param [path] payload_path The payload path on disk
    # @param [Hash] opts the opts to pass to the Process#spawn call
    def initialize(cmd, payload_path, opts = {})
      super()

      @payload_path = payload_path
      @debug = false
      @env = {}
      @cmd = cmd
      @options = opts
    end

    # @return [Process::Waiter] the waiter thread for the payload process
    def run
      pid = Process.spawn(
        @env,
        *@cmd,
        **@options
      )
      @wait_thread = Process.detach(pid)
      @wait_thread
    end

    def alive?
      @wait_thread.alive?
    end

    def close
      begin
        Process.kill('KILL', wait_thread.pid) if wait_thread.pid
      rescue StandardError => e
        warn "error #{e} for #{@cmd}, pid #{wait_thread.pid}"
      end
      [:in, :out, :err].each do |name|
        @options[name].close if @options[name]
      end
      @wait_thread.join
    end
  end

  class ConsoleDriver
    def initialize
      @console = nil
      @payload_processes = []
      ObjectSpace.define_finalizer(self, self.class.finalizer_proc_for(self))
    end

    # @param [Acceptance::Payload] payload
    # @param [Hash] opts
    def run_payload(payload, opts)
      if payload.executable? && !File.executable?(payload.path)
        FileUtils.chmod('+x', payload.path)
      end

      payload_process = PayloadProcess.new(payload.execute_command, payload.path, opts)
      payload_process.run
      @payload_processes << payload_process
      payload_process
    end

    # @return [Acceptance::Console]
    def open_console
      @console = Console.new
      @console.run
      @console.recvuntil(Console.prompt, timeout: 120)

      @console
    end

    def close_payloads
      close_processes(@payload_processes)
    end

    def close
      close_processes(@payload_processes + [console])
    end

    def self.finalizer_proc_for(instance)
      proc { instance.close }
    end

    private

    def close_processes(processes)
      while (process = processes.pop)
        begin
          process.close
        rescue StandardError => e
          $stderr.puts e.to_s
        end
      end
    end
  end

  class Console < ChildProcess
    def initialize
      super

      framework_root = Dir.pwd
      @debug = true
      @env = {
        'BUNDLE_GEMFILE' => File.join(framework_root, 'Gemfile'),
        'PATH' => "#{framework_root.shellescape}:#{ENV['PATH']}"
      }
      @cmd = [
        'bundle', 'exec', 'ruby', 'msfconsole',
        '--no-readline',
        # '--logger', 'Stdout',
        '--quiet'
      ]
      @options = {
        chdir: framework_root
      }
    end

    def self.prompt
      /msf6.*>\s+/
    end

    def reset
      sendline('sessions -K')
      recvuntil(Console.prompt)

      sendline('jobs -K')
      recvuntil(Console.prompt)
    ensure
      @all_data.reopen('')
    end
  end
end
