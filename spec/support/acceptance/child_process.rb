# require 'stringio'
require 'open3'
require 'English'
require 'tempfile'
require 'fileutils'
require 'timeout'
require 'shellwords'

module Acceptance
  class ChildProcess
    def initialize
      super

      @default_timeout = ENV['CI'] ? 30 : 15
      @debug = true
      @env ||= {}
      @cmd ||= []
      @options ||= {}

      @stdin = nil
      @stdout_and_stderr = nil
      @wait_thread = nil

      @buffer = StringIO.new
      @all_data = StringIO.new
    end

    def all_data
      @all_data.string
    end

    def run
      self.stdin, self.stdout_and_stderr, self.wait_thread = ::Open3.popen2e(
        @env,
        *@cmd,
        **@options
      )

      stdin.sync = true
      stdout_and_stderr.sync = true
    rescue StandardError => e
      warn "popen failure #{e}"
      raise
    end

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
          # clear our temporary buffer
          buffer = ''

          return result
        end
      ensure
        unrecv(buffer)
      end

      result
    end

    def recvall(timeout: @default_timeout)
      result = ''

      with_countdown(timeout) do |countdown|
        while alive? && !countdown.elapsed?
          data_chunk = recv(timeout: countdown.remaining_time)
          if !data_chunk
            next
          end

          result += data_chunk
        end
      end

      result
    end

    def unrecv(data)
      buffer.write(data)
      buffer.pos = [0, buffer.pos - data.length].max
    end

    def recv(size = 4096, timeout: @default_timeout)
      buffer_result = buffer.read(size)
      return buffer_result if buffer_result

      retry_count = 0

      # Eagerly read, and if we fail - await a response within the given timeout period
      begin
        result = stdout_and_stderr.read_nonblock(size)
        if !result.nil?
          log("[read] #{result}")
          @all_data.write(result)
        end
      rescue IO::WaitReadable
        IO.select([stdout_and_stderr], nil, nil, timeout)
        retry_count += 1
        retry if retry_count == 1
      end

      result
    end

    def write(data)
      log("[write] #{data}")
      @all_data.write(data)
      stdin.write(data)
      stdin.flush
    end

    def sendline(s)
      write("#{s}#{$INPUT_RECORD_SEPARATOR}")
    end

    def alive?
      wait_thread.alive?
    end

    # Interact with the current process, forwarding the current stdin to the console's stdin,
    # and writing the console's output to stdout. Doesn't support using PTY/raw mode.
    def interact
      $stderr.puts
      warn '[*] Opened interactive mode - enter "!next" to continue, or "!exit" to stop entirely'
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
      stdin.close if stdin
      stdout_and_stderr.close if stdout_and_stderr
      begin
        Process.kill('KILL', wait_thread.pid) if wait_thread.pid
      rescue StandardError => e
        warn "error #{e} for #{@cmd}, pid #{wait_thread.pid}"
      end
    end

    # @return [IO] the stdin for the child process which can be written to
    attr_reader :stdin
    # @return [IO] the stdout and stderr for the child process which can be read from
    attr_reader :stdout_and_stderr
    # @return [Process::Waiter] the waiter thread for the current process
    attr_reader :wait_thread

    private

    # @return [StringIO] the buffer for any data which was read from stdout/stderr which was read, but not consumed
    attr_reader :buffer
    attr_writer :stdin, :stdout_and_stderr, :wait_thread

    def log(s)
      return unless @debug

      warn s
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
      countdown = Countdown.new(timeout)
      # It is the caller's responsibility to honor the required countdown limits,
      # but let's wrap the full operation in an explicit for worse case scenario,
      # which may leave object state in a non-determinant state depending on the call
      ::Timeout.timeout(timeout * 1.5) do
        yield countdown
      end
      if countdown.elapsed?
        raise "Failed await result, remaining buffer: #{buffer.string[buffer.pos..].inspect}"
      end
    end
  end

  ###
  # Stores the data for a payload, including the options used to generate the payload,
  ###
  class Payload
    attr_reader :name, :execute_cmd, :generate_options, :payload_options

    def initialize(options)
      @name = options.fetch(:name)
      @execute_cmd = options.fetch(:execute_cmd)
      @generate_options = options.fetch(:generate_options)
      @payload_options = options.fetch(:payload_options)
      @executable = options.fetch(:executable, false)

      basename = "#{File.basename(__FILE__)}_#{name}".gsub(/[^a-zA-Z]/, '-')
      extension = options.fetch(:extension, '')
      # Generate a Dir::Tmpname instead of a Tempfile, otherwise windows won't allow the file to be executed
      # as the current Ruby process will still have a handle to it
      # TODO: Ensure this is deleted correctly
      @file_path = Dir::Tmpname.create([basename, extension]) do |_path, _n, _opts, _origdir|
        # noop
      end

      ObjectSpace.define_finalizer(self, self.class.finalizer_proc_for(@file_path))
    end

    # @return [TrueClass, FalseClass] True if the payload needs marked as executable before being executed
    def executable?
      @executable
    end

    # @return [String] The path to the payload on disk
    def path
      @file_path
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

    # @return [String] The command which can be used on msfconsole to generate the payload
    def generate_command
      default_payload_options = {
        AutoVerifySessionTimeout: 10
      }
      payload_options = default_payload_options.merge(@payload_options)
      generate_options = @generate_options.map do |key, value|
        "#{key} #{value}"
      end
      payload_options = payload_options.map do |key, value|
        "#{key}=#{value}"
      end

      "generate -o #{path} #{generate_options.join(' ')} #{payload_options.join(' ')}"
    end

    # @return [String] A human readable representation of the payload configuration object
    def as_readable_text
      <<~EOF
        ## Payload
        use #{name}

        ## Generate command
        #{generate_command}

        ## Create listener
        to_handler

        ## Execute command
        #{Shellwords.join(execute_command)}
      EOF
    end

    def self.finalizer_proc_for(path)
      proc { File.delete(path) if File.exist?(path) }
    end
  end

  class PayloadProcess < ChildProcess
    # @param [Array<String>] cmd The command which can be used to execute this payload. For instance ["python3", "/tmp/path.py"]
    def initialize(cmd)
      super()

      @env = {}
      @cmd = cmd
      @options = {}
    end
  end

  class ConsoleDriver
    def initialize
      @coonsole = nil
      @payload_processes = []
      ObjectSpace.define_finalizer(self, self.class.finalizer_proc_for(self))
    end

    # @param [Acceptance::Payload] payload
    def run_payload(payload)
      if payload.executable? && !File.executable?(payload.path)
        FileUtils.chmod('+x', payload.path)
      end

      payload_process = PayloadProcess.new(payload.execute_command)
      payload_process.run
      @payload_processes << payload_process
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
          warn e.to_s
        end
      end
    end
  end

  class Console < ChildProcess
    def initialize
      super

      framework_root = Dir.pwd
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

      @all_data.reopen('')
    end
  end
end
