#
# Standard Library
#

require 'securerandom'

#
# Project
#

require 'metasploit/framework/spec/threads/suite'

original_thread_new = Thread.method(:new)

# Patches `Thread.new` so that if logs `caller` so thread leaks can be traced
Thread.define_singleton_method(:new) { |*args, &block|
  uuid = SecureRandom.uuid
  # tag caller with uuid so that only leaked threads caller needs to be printed
  lines = ["BEGIN Thread.new caller (#{uuid})"]

  caller.each do |frame|
    lines << "  #{frame}"
  end

  lines << 'END Thread.new caller'

  Metasploit::Framework::Spec::Threads::Suite::LOG_PATHNAME.parent.mkpath

  Metasploit::Framework::Spec::Threads::Suite::LOG_PATHNAME.open('a') { |f|
    # single puts so threads can't write in between each other.
    f.puts lines.join("\n")
  }

  options = {original_args: args, uuid: uuid}

  original_thread_new.call(options) {
    # record uuid for thread-leak detection can used uuid to correlate log with this thread.
    Thread.current[Metasploit::Framework::Spec::Threads::Suite::UUID_THREAD_LOCAL_VARIABLE] = options.fetch(:uuid)
    block.call(*options.fetch(:original_args))
  }
}