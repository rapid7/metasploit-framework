class Array
  @@to_s_reported = {}
  def to_s(*args)
    if(not @@to_s_reported[caller[0].to_s])
      $stderr.puts "HOOK: Array#to_s at #{caller.join("\t")}"
      @@to_s_reported[caller[0].to_s] = true
    end
    super(*args)
  end
end
