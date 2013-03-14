# A helper class that allows you to run a block inside of a fork, and then get the result from that block.
#
# == Example:
#
#   forker = Spork::Forker.new do
#     sleep 3
#     "success"
#   end
#   
#   forker.result # => "success"
class Spork::Forker
  
  # Raised if the fork died (was killed) before it sent it's response back.
  class ForkDiedException < Exception; end
  def initialize(&block)
    return unless block_given?
    @child_io, @server_io = UNIXSocket.socketpair
    @child_pid = Kernel.fork do
      begin
        @server_io.close
        Marshal.dump(yield, @child_io)
        # wait for the parent to acknowledge receipt of the result.
        master_response = Marshal.load(@child_io)
      rescue EOFError
        nil
      rescue Exception => e
        puts "Exception encountered: #{e.inspect}\nbacktrace:\n#{e.backtrace * %(\n)}"
      end
      
      # terminate, skipping any at_exit blocks.
      exit!(0)
    end
    @child_io.close
  end
  
  # Wait for the fork to finish running, and then return its return value.
  #
  # If the fork was aborted, then result returns nil.
  def result
    return unless running?
    result_thread = Thread.new do
      begin
        @result = Marshal.load(@server_io)
        Marshal.dump('ACK', @server_io)
      rescue ForkDiedException, EOFError
        @result = nil
      end
    end
    Process.wait(@child_pid)
    result_thread.raise(ForkDiedException) if @result.nil?
    @child_pid = nil
    @result
  end
  
  # abort the current running fork
  def abort
    if running?
      Process.kill(Signal.list['TERM'], @child_pid)
      @child_pid = nil
      true
    end
  end
  
  def running?
    return false unless @child_pid
    Process.getpgid(@child_pid)
    true
  rescue Errno::ESRCH
    false
  end
end
