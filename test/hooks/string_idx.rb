class String
  @@idx_reported = {}
  def [](*args)
  
    if(args.length == 1 and args[0].class == ::Fixnum and not @@idx_reported[caller[0].to_s])
      $stderr.puts "HOOK: String[idx] #{caller.join("\t")}\n\n"
      @@idx_reported[caller[0].to_s] = true
    end
    slice(*args)
  end
end
