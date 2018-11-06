require 'arel/visitors/depth_first'

module Arel
  module Visitors
    class DepthFirst
      alias :visit_IPAddr :terminal
    end
  end
end
