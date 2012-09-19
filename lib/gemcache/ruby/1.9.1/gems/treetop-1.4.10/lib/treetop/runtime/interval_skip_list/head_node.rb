class IntervalSkipList
  class HeadNode
    attr_reader :height, :forward, :forward_markers

    def initialize(height)
      @height = height
      @forward = Array.new(height, nil)
      @forward_markers = Array.new(height) {|i| []}
    end

    def top_level
      height - 1
    end
  end
end