unless Object.const_defined? :StopIteration
  require 'backports/tools/alias_method_chain'

  class StopIteration < IndexError; end

  module Kernel
    def loop_with_stop_iteration(&block)
      loop_without_stop_iteration(&block)
    rescue StopIteration
      # ignore silently
    end
    Backports.alias_method_chain self, :loop, :stop_iteration
  end
end
