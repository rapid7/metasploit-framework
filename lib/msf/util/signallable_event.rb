module Msf                                            
module Util
class SignallableEvent
  def initialize
    @mutex = Mutex.new
    @cv = ConditionVariable.new
    @val = false
  end

  def signal()
    @mutex.synchronize do
      @val = true
      @cv.signal
    end
  end

  # Wait for the event to be signalled, or the timeout.
  # Resets the event following the call
  # Returns true if the event was signalled, or false if not
  # Returns immediately if the event was already signalled upon entry
  def wait(timeout)
    @mutex.synchronize do
      unless @val
        @cv.wait(@mutex, timeout)
      end
      result = @val
      @val = false
      return result
    end
  end
end
end
end
