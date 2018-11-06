module ElapsedTime
  def print_elapsed_time(io, start_time)
    if ENV['FIVEMAT_PROFILE']
      elapsed_time = (((Time.now - start_time) * 100).to_i / 100.0)
      io.print " (#{elapsed_time}s)"
    end
  end
end

