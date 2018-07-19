# -*- coding: binary -*-
# Namespace for loading external Metasploit modules

class Msf::Modules::External

  autoload :Bridge, 'msf/core/modules/external/bridge'
  autoload :Message, 'msf/core/modules/external/message'
  autoload :CLI, 'msf/core/modules/external/cli'

  attr_reader :path

  def meta
    @meta ||= describe
  end

  def initialize(module_path, framework: nil)
    self.path = module_path
    self.framework = framework
  end

  def exec(method: :run, args: {}, &block)
    req = Message.new(method)
    req.params = args.dup

    b = Bridge.open(self.path, framework: self.framework).exec(req)

    if block
      begin
        while m = b.messages.pop
          block.call m
        end
      ensure
        b.close
      end
      return b.success?
    else
      return b
    end
  end

  protected

  attr_writer :path
  attr_accessor :framework

  def describe
    exec method: :describe do |msg|
      return msg.params if msg.method == :reply
    end
  end
end
