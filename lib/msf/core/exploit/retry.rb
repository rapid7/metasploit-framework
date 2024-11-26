module Msf::Exploit::Retry
  # Retry the block until it returns a truthy value. Each iteration attempt will
  # be performed with an exponential backoff. If the timeout period surpasses,
  # nil is returned.
  #
  # @param Integer timeout the number of seconds to wait before the operation times out
  # @return the truthy value of the block is returned or nil if it timed out
  def retry_until_truthy(timeout:)
    start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC, :second)
    ending_time = start_time + timeout
    retry_count = 0
    while Process.clock_gettime(Process::CLOCK_MONOTONIC, :second) < ending_time
      result = yield
      return result if result

      retry_count += 1
      remaining_time_budget = ending_time - Process.clock_gettime(Process::CLOCK_MONOTONIC, :second)
      break if remaining_time_budget <= 0

      delay = 2**retry_count
      if delay >= remaining_time_budget
        delay = remaining_time_budget
        vprint_status("Final attempt. Sleeping for the remaining #{delay} seconds out of total timeout #{timeout}")
      else
        vprint_status("Sleeping for #{delay} seconds before attempting again")
      end

      sleep delay
    end

    nil
  end
end
