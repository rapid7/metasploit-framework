module Kernel
  # Suppresses any warnings raised in a specified block.
  def without_warnings
    old_verbose = $VERBOSE
    begin
      $VERBOSE = nil
      yield
    ensure
      $-v = old_verbose
    end
  end
  
  def safe_test(level = 1)
    thread = Thread.new do
      $SAFE = level
      yield
    end
    
    thread.join
  end
end