module Acceptance
  ###
  # A utility class for generating the next available bind port that is free
  # on the host machine
  ###
  class PortAllocator
    def initialize(base = 6000)
      @base = base
      @current = base
    end

    # @return [Integer] The next available port that can be bound to on the host
    def next
      # TODO: In the future this could verify the port is free, and attempt to avoid TOCTTOU issues
      @current += 1
    end
  end
end
