require 'metasploit/framework/spec/threads/suite'

original_thread_new = Thread.method(:new)

# Patches `Thread.new` so that if logs `caller` so thread leaks can be traced
Thread.define_singleton_method(:new) { |*args, &block|
  lines = ['BEGIN Thread.new caller']

  caller.each do |frame|
    lines << "  #{frame}"
  end

  lines << 'END Thread.new caller'

  Metasploit::Framework::Spec::Threads::Suite::LOG_PATHNAME.parent.mkpath

  Metasploit::Framework::Spec::Threads::Suite::LOG_PATHNAME.open('a') { |f|
    # single puts so threads can't write in between each other.
    f.puts lines.join("\n")
  }

  original_thread_new.call(*args, &block)
}