# -*- ruby encoding: utf-8 -*-

class << Diff::LCS
  def diff_traversal(method, seq1, seq2, callbacks, &block)
    callbacks = callbacks_for(callbacks)
    case method
    when :diff
      traverse_sequences(seq1, seq2, callbacks)
    when :sdiff
      traverse_balanced(seq1, seq2, callbacks)
    end
    callbacks.finish if callbacks.respond_to? :finish

    if block
      callbacks.diffs.map do |hunk|
        if hunk.kind_of? Array
          hunk.map { |hunk_block| block[hunk_block] }
        else
          block[hunk]
        end
      end
    else
      callbacks.diffs
    end
  end
  private :diff_traversal
end

module Diff::LCS::Internals # :nodoc:
end

class << Diff::LCS::Internals
  # Compute the longest common subsequence between the sequenced
  # Enumerables +a+ and +b+. The result is an array whose contents is such
  # that
  #
  #     result = Diff::LCS::Internals.lcs(a, b)
  #     result.each_with_index do |e, i|
  #       assert_equal(a[i], b[e]) unless e.nil?
  #     end
  def lcs(a, b)
    a_start = b_start = 0
    a_finish = a.size - 1
    b_finish = b.size - 1
    vector = []

    # Prune off any common elements at the beginning...
    while ((a_start <= a_finish) and (b_start <= b_finish) and
           (a[a_start] == b[b_start]))
      vector[a_start] = b_start
      a_start += 1
      b_start += 1
    end
    b_start = a_start

    # Now the end...
    while ((a_start <= a_finish) and (b_start <= b_finish) and
           (a[a_finish] == b[b_finish]))
      vector[a_finish] = b_finish
      a_finish -= 1
      b_finish -= 1
    end

    # Now, compute the equivalence classes of positions of elements.
    b_matches = position_hash(b, b_start..b_finish)

    thresh = []
    links  = []
    string = a.kind_of?(String)

    (a_start .. a_finish).each do |i|
      ai = string ? a[i, 1] : a[i]
      bm = b_matches[ai]
      k = nil
      bm.reverse_each do |j|
        if k and (thresh[k] > j) and (thresh[k - 1] < j)
          thresh[k] = j
        else
          k = replace_next_larger(thresh, j, k)
        end
        links[k] = [ (k > 0) ? links[k - 1] : nil, i, j ] unless k.nil?
      end
    end

    unless thresh.empty?
      link = links[thresh.size - 1]
      while not link.nil?
        vector[link[1]] = link[2]
        link = link[0]
      end
    end

    vector
  end

  # This method will analyze the provided patchset to provide a
  # single-pass normalization (conversion of the array form of
  # Diff::LCS::Change objects to the object form of same) and detection of
  # whether the patchset represents changes to be made.
  def analyze_patchset(patchset, depth = 0)
    raise "Patchset too complex" if depth > 1

    has_changes = false

    # Format:
    # [ # patchset
    #   # hunk (change)
    #   [ # hunk
    #     # change
    #   ]
    # ]

    patchset = patchset.map do |hunk|
      case hunk
      when Diff::LCS::Change
        has_changes ||= !hunk.unchanged?
        hunk
      when Array
        # Detect if the 'hunk' is actually an array-format
        # Change object.
        if Diff::LCS::Change.valid_action? hunk[0]
          hunk = Diff::LCS::Change.from_a(hunk)
          has_changes ||= !hunk.unchanged?
          hunk
        else
          with_changes, hunk = analyze_patchset(hunk, depth + 1)
          has_changes ||= with_changes
          hunk.flatten
        end
      else
        raise ArgumentError, "Cannot normalise a hunk of class #{hunk.class}."
      end
    end

    [ has_changes, patchset.flatten(1) ]
  end

  # Examine the patchset and the source to see in which direction the
  # patch should be applied.
  #
  # WARNING: By default, this examines the whole patch, so this could take
  # some time. This also works better with Diff::LCS::ContextChange or
  # Diff::LCS::Change as its source, as an array will cause the creation
  # of one of the above.
  def intuit_diff_direction(src, patchset, limit = nil)
    string = src.kind_of?(String)
    count = left_match = left_miss = right_match = right_miss = 0

    patchset.each do |change|
      count += 1

      case change
      when Diff::LCS::ContextChange
        le = string ? src[change.old_position, 1] : src[change.old_position]
        re = string ? src[change.new_position, 1] : src[change.new_position]

        case change.action
        when '-' # Remove details from the old string
          if le == change.old_element
            left_match += 1
          else
            left_miss += 1
          end
        when '+'
          if re == change.new_element
            right_match += 1
          else
            right_miss += 1
          end
        when '='
          left_miss += 1 if le != change.old_element
          right_miss += 1 if re != change.new_element
        when '!'
          if le == change.old_element
            left_match += 1
          else
            if re == change.new_element
              right_match += 1
            else
              left_miss += 1
              right_miss += 1
            end
          end
        end
      when Diff::LCS::Change
        # With a simplistic change, we can't tell the difference between
        # the left and right on '!' actions, so we ignore those. On '='
        # actions, if there's a miss, we miss both left and right.
        element = string ? src[change.position, 1] : src[change.position]

        case change.action
        when '-'
          if element == change.element
            left_match += 1
          else
            left_miss += 1
          end
        when '+'
          if element == change.element
            right_match += 1
          else
            right_miss += 1
          end
        when '='
          if element != change.element
            left_miss += 1
            right_miss += 1
          end
        end
      end

      break if (not limit.nil?) && (count > limit)
    end

    no_left = (left_match == 0) && (left_miss > 0)
    no_right = (right_match == 0) && (right_miss > 0)

    case [ no_left, no_right ]
    when [ false, true ]
      :patch
    when [ true, false ]
      :unpatch
    else
      case left_match <=> right_match
      when 1
        if left_miss.zero?
          :patch
        else
          :unpatch
        end
      when -1
        if right_miss.zero?
          :unpatch
        else
          :patch
        end
      else
        raise "The provided patchset does not appear to apply to the provided enumerable as either source or destination value."
      end
    end
  end

  # Find the place at which +value+ would normally be inserted into the
  # Enumerable. If that place is already occupied by +value+, do nothing
  # and return +nil+. If the place does not exist (i.e., it is off the end
  # of the Enumerable), add it to the end. Otherwise, replace the element
  # at that point with +value+. It is assumed that the Enumerable's values
  # are numeric.
  #
  # This operation preserves the sort order.
  def replace_next_larger(enum, value, last_index = nil)
    # Off the end?
    if enum.empty? or (value > enum[-1])
      enum << value
      return enum.size - 1
    end

    # Binary search for the insertion point
    last_index ||= enum.size
    first_index = 0
    while (first_index <= last_index)
      i = (first_index + last_index) >> 1

      found = enum[i]

      if value == found
        return nil
      elsif value > found
        first_index = i + 1
      else
        last_index = i - 1
      end
    end

    # The insertion point is in first_index; overwrite the next larger
    # value.
    enum[first_index] = value
    return first_index
  end
  private :replace_next_larger

  # If +vector+ maps the matching elements of another collection onto this
  # Enumerable, compute the inverse of +vector+ that maps this Enumerable
  # onto the collection. (Currently unused.)
  def inverse_vector(a, vector)
    inverse = a.dup
    (0...vector.size).each do |i|
      inverse[vector[i]] = i unless vector[i].nil?
    end
    inverse
  end
  private :inverse_vector

  # Returns a hash mapping each element of an Enumerable to the set of
  # positions it occupies in the Enumerable, optionally restricted to the
  # elements specified in the range of indexes specified by +interval+.
  def position_hash(enum, interval)
    string = enum.kind_of?(String)
    hash = Hash.new { |h, k| h[k] = [] }
    interval.each do |i|
      k = string ? enum[i, 1] : enum[i]
      hash[k] << i
    end
    hash
  end
  private :position_hash
end
