class IntervalSkipList
  class Node < HeadNode
    attr_accessor :key
    attr_reader :markers, :endpoint_of

    def initialize(key, height, path)
      super(height)
      @key = key
      @markers = []
      @endpoint_of = []
      update_forward_pointers(path)
      promote_markers(path)
    end

    def all_forward_markers
      markers.flatten
    end

    def delete(path)
      0.upto(top_level) do |i|
        path[i].forward[i] = forward[i]
      end
      demote_markers(path)
    end

    def propagate_length_change(length_change)
      cur_node = self
      while cur_node do
        cur_node.key += length_change
        cur_node = cur_node.forward[0]
      end
    end

    protected

    def update_forward_pointers(path)
      0.upto(top_level) do |i|
        forward[i] = path[i].forward[i]
        path[i].forward[i] = self
      end
    end

    def promote_markers(path)
      promoted = []
      new_promoted = []
      0.upto(top_level) do |i|
        incoming_markers = path[i].forward_markers[i]
        markers.concat(incoming_markers)

        incoming_markers.each do |marker|
          if can_be_promoted_higher?(marker, i)
            new_promoted.push(marker)
            forward[i].delete_marker_from_path(marker, i, forward[i+1])
          else
            forward_markers[i].push(marker)
          end
        end

        promoted.each do |marker|
          if can_be_promoted_higher?(marker, i)
            new_promoted.push(marker)
            forward[i].delete_marker_from_path(marker, i, forward[i+1])
          else
            forward_markers[i].push(marker)
          end
        end

        promoted = new_promoted
        new_promoted = []
      end
    end


    def can_be_promoted_higher?(marker, level)
      level < top_level && forward[level + 1] && forward[level + 1].markers.include?(marker)
    end

    def delete_marker_from_path(marker, level, terminus)
      cur_node = self
      until cur_node == terminus
        cur_node.forward_markers[level].delete(marker)
        cur_node.markers.delete(marker)
        cur_node = cur_node.forward[level]
      end
    end

    def demote_markers(path)
      demote_inbound_markers(path)
      demote_outbound_markers(path)
    end

    def demote_inbound_markers(path)
      demoted = []
      new_demoted = []

      top_level.downto(0) do |i|
        incoming_markers = path[i].forward_markers[i].dup
        incoming_markers.each do |marker|
          unless forward_node_with_marker_at_or_above_level?(marker, i)
            path[i].forward_markers[i].delete(marker)
            new_demoted.push(marker)
          end
        end

        demoted.each do |marker|
          path[i + 1].place_marker_on_inbound_path(marker, i, path[i])

          if forward[i].markers.include?(marker)
            path[i].forward_markers[i].push(marker)
          else
            new_demoted.push(marker)
          end
        end

        demoted = new_demoted
        new_demoted = []
      end
    end

    def demote_outbound_markers(path)
      demoted = []
      new_demoted = []

      top_level.downto(0) do |i|
        forward_markers[i].each do |marker|
          new_demoted.push(marker) unless path[i].forward_markers[i].include?(marker)
        end

        demoted.each do |marker|
          forward[i].place_marker_on_outbound_path(marker, i, forward[i + 1])
          new_demoted.push(marker) unless path[i].forward_markers[i].include?(marker)
        end

        demoted = new_demoted
        new_demoted = []
      end
    end

    def forward_node_with_marker_at_or_above_level?(marker, level)
      level.upto(top_level) do |i|
        return true if forward[i].markers.include?(marker)
      end
      false
    end

    def place_marker_on_outbound_path(marker, level, terminus)
      cur_node = self
      until cur_node == terminus
        cur_node.forward_markers[level].push(marker)
        cur_node.markers.push(marker)
        cur_node = cur_node.forward[level]
      end
    end

    def place_marker_on_inbound_path(marker, level, terminus)
      cur_node = self
      until cur_node == terminus
        cur_node.forward_markers[level].push(marker)
        cur_node = cur_node.forward[level]
        cur_node.markers.push(marker)
      end
    end
  end
end