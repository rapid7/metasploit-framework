class BackgroundJob
  attr_reader :stdin, :stdout, :stderr, :pid
  def initialize(pid, stdin, stdout, stderr)
    @pid, @stdin, @stdout, @stderr = pid, stdin, stdout, stderr
    ObjectSpace.define_finalizer(self) { kill }
  end

  def self.run(command)
    command = sanitize_params(command) if command.is_a?(Array)
    child_stdin, parent_stdin = IO::pipe
    parent_stdout, child_stdout = IO::pipe
    parent_stderr, child_stderr = IO::pipe

    pid = Kernel.fork do
      [parent_stdin, parent_stdout, parent_stderr].each { |io| io.close }

      STDIN.reopen(child_stdin)
      STDOUT.reopen(child_stdout)
      STDERR.reopen(child_stderr)

      [child_stdin, child_stdout, child_stderr].each { |io| io.close }

      exec command
    end

    [child_stdin, child_stdout, child_stderr].each { |io| io.close }
    parent_stdin.sync = true

    new(pid, parent_stdin, parent_stdout, parent_stderr)
  end

  def self.sanitize_params(params)
    params.map { |p| p.gsub(' ', '\ ') }.join(" ")
  end

  def kill(signal = 'TERM')
    if running?
      Process.kill(Signal.list[signal], @pid)
      true
    end
  end

  def interrupt
    kill('INT')
  end

  def running?
    return false unless @pid
    Process.getpgid(@pid)
    true
  rescue Errno::ESRCH
    false
  end

  def wait(timeout = 1000)
    Timeout.timeout(timeout) do
      Process.wait(@pid)
    end
    true
  rescue Timeout::Error
    false
  end
end
