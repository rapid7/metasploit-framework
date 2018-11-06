# -*- ruby encoding: utf-8 -*-

module Diff; end unless defined? Diff
# == How Diff Works (by Mark-Jason Dominus)
#
# I once read an article written by the authors of +diff+; they said that
# they hard worked very hard on the algorithm until they found the right
# one.
#
# I think what they ended up using (and I hope someone will correct me,
# because I am not very confident about this) was the `longest common
# subsequence' method. In the LCS problem, you have two sequences of items:
#
#    a b c d f g h j q z
#    a b c d e f g i j k r x y z
#
# and you want to find the longest sequence of items that is present in both
# original sequences in the same order. That is, you want to find a new
# sequence *S* which can be obtained from the first sequence by deleting
# some items, and from the second sequence by deleting other items. You also
# want *S* to be as long as possible. In this case *S* is:
#
#    a b c d f g j z
#
# From there it's only a small step to get diff-like output:
#
#    e   h i   k   q r x y
#    +   - +   +   - + + +
#
# This module solves the LCS problem. It also includes a canned function to
# generate +diff+-like output.
#
# It might seem from the example above that the LCS of two sequences is
# always pretty obvious, but that's not always the case, especially when the
# two sequences have many repeated elements. For example, consider
#
#    a x b y c z p d q
#    a b c a x b y c z
#
# A naive approach might start by matching up the +a+ and +b+ that appear at
# the beginning of each sequence, like this:
#
#    a x b y c         z p d q
#    a   b   c a b y c z
#
# This finds the common subsequence +a b c z+. But actually, the LCS is +a x
# b y c z+:
#
#          a x b y c z p d q
#    a b c a x b y c z
module Diff::LCS
  VERSION = '1.3'
end

require 'diff/lcs/callbacks'
require 'diff/lcs/internals'

module Diff::LCS
  # Returns an Array containing the longest common subsequence(s) between
  # +self+ and +other+. See Diff::LCS#LCS.
  #
  #   lcs = seq1.lcs(seq2)
  def lcs(other, &block) #:yields self[i] if there are matched subsequences:
    Diff::LCS.lcs(self, other, &block)
  end

  # Returns the difference set between +self+ and +other+. See
  # Diff::LCS#diff.
  def diff(other, callbacks = nil, &block)
    Diff::LCS.diff(self, other, callbacks, &block)
  end

  # Returns the balanced ("side-by-side") difference set between +self+ and
  # +other+. See Diff::LCS#sdiff.
  def sdiff(other, callbacks = nil, &block)
    Diff::LCS.sdiff(self, other, callbacks, &block)
  end

  # Traverses the discovered longest common subsequences between +self+ and
  # +other+. See Diff::LCS#traverse_sequences.
  def traverse_sequences(other, callbacks = nil, &block)
    traverse_sequences(self, other, callbacks ||
                       Diff::LCS.YieldingCallbacks, &block)
  end

  # Traverses the discovered longest common subsequences between +self+ and
  # +other+ using the alternate, balanced algorithm. See
  # Diff::LCS#traverse_balanced.
  def traverse_balanced(other, callbacks = nil, &block)
    traverse_balanced(self, other, callbacks ||
                      Diff::LCS.YieldingCallbacks, &block)
  end

  # Attempts to patch +self+ with the provided +patchset+. A new sequence
  # based on +self+ and the +patchset+ will be created. See Diff::LCS#patch.
  # Attempts to autodiscover the direction of the patch.
  def patch(patchset)
    Diff::LCS.patch(self, patchset)
  end
  alias_method :unpatch, :patch

  # Attempts to patch +self+ with the provided +patchset+. A new sequence
  # based on +self+ and the +patchset+ will be created. See Diff::LCS#patch.
  # Does no patch direction autodiscovery.
  def patch!(patchset)
    Diff::LCS.patch!(self, patchset)
  end

  # Attempts to unpatch +self+ with the provided +patchset+. A new sequence
  # based on +self+ and the +patchset+ will be created. See Diff::LCS#unpatch.
  # Does no patch direction autodiscovery.
  def unpatch!(patchset)
    Diff::LCS.unpatch!(self, patchset)
  end

  # Attempts to patch +self+ with the provided +patchset+, using #patch!. If
  # the sequence this is used on supports #replace, the value of +self+ will
  # be replaced. See Diff::LCS#patch. Does no patch direction autodiscovery.
  def patch_me(patchset)
    if respond_to? :replace
      replace(patch!(patchset))
    else
      patch!(patchset)
    end
  end

  # Attempts to unpatch +self+ with the provided +patchset+, using
  # #unpatch!. If the sequence this is used on supports #replace, the value
  # of +self+ will be replaced. See Diff::LCS#unpatch. Does no patch direction
  # autodiscovery.
  def unpatch_me(patchset)
    if respond_to? :replace
      replace(unpatch!(patchset))
    else
      unpatch!(patchset)
    end
  end
end

class << Diff::LCS
  def lcs(seq1, seq2, &block) #:yields seq1[i] for each matched:
    matches = Diff::LCS::Internals.lcs(seq1, seq2)
    ret = []
    string = seq1.kind_of? String
    matches.each_with_index do |e, i|
      unless matches[i].nil?
        v = string ? seq1[i, 1] : seq1[i]
        v = block[v] if block
        ret << v
      end
    end
    ret
  end
  alias_method :LCS, :lcs

  # #diff computes the smallest set of additions and deletions necessary to
  # turn the first sequence into the second, and returns a description of
  # these changes.
  #
  # See Diff::LCS::DiffCallbacks for the default behaviour. An alternate
  # behaviour may be implemented with Diff::LCS::ContextDiffCallbacks. If a
  # Class argument is provided for +callbacks+, #diff will attempt to
  # initialise it. If the +callbacks+ object (possibly initialised) responds
  # to #finish, it will be called.
  def diff(seq1, seq2, callbacks = nil, &block) # :yields diff changes:
    diff_traversal(:diff, seq1, seq2, callbacks || Diff::LCS::DiffCallbacks,
                   &block)
  end

  # #sdiff computes all necessary components to show two sequences and their
  # minimized differences side by side, just like the Unix utility
  # <em>sdiff</em> does:
  #
  #     old        <     -
  #     same             same
  #     before     |     after
  #     -          >     new
  #
  # See Diff::LCS::SDiffCallbacks for the default behaviour. An alternate
  # behaviour may be implemented with Diff::LCS::ContextDiffCallbacks. If a
  # Class argument is provided for +callbacks+, #diff will attempt to
  # initialise it. If the +callbacks+ object (possibly initialised) responds
  # to #finish, it will be called.
  def sdiff(seq1, seq2, callbacks = nil, &block) #:yields diff changes:
    diff_traversal(:sdiff, seq1, seq2, callbacks || Diff::LCS::SDiffCallbacks,
                   &block)
  end

  # #traverse_sequences is the most general facility provided by this
  # module; #diff and #lcs are implemented as calls to it.
  #
  # The arguments to #traverse_sequences are the two sequences to traverse,
  # and a callback object, like this:
  #
  #   traverse_sequences(seq1, seq2, Diff::LCS::ContextDiffCallbacks.new)
  #
  # == Callback Methods
  #
  # Optional callback methods are <em>emphasized</em>.
  #
  # callbacks#match::               Called when +a+ and +b+ are pointing to
  #                                 common elements in +A+ and +B+.
  # callbacks#discard_a::           Called when +a+ is pointing to an
  #                                 element not in +B+.
  # callbacks#discard_b::           Called when +b+ is pointing to an
  #                                 element not in +A+.
  # <em>callbacks#finished_a</em>:: Called when +a+ has reached the end of
  #                                 sequence +A+.
  # <em>callbacks#finished_b</em>:: Called when +b+ has reached the end of
  #                                 sequence +B+.
  #
  # == Algorithm
  #
  #       a---+
  #           v
  #       A = a b c e h j l m n p
  #       B = b c d e f j k l m r s t
  #           ^
  #       b---+
  #
  # If there are two arrows (+a+ and +b+) pointing to elements of sequences
  # +A+ and +B+, the arrows will initially point to the first elements of
  # their respective sequences. #traverse_sequences will advance the arrows
  # through the sequences one element at a time, calling a method on the
  # user-specified callback object before each advance. It will advance the
  # arrows in such a way that if there are elements <tt>A[i]</tt> and
  # <tt>B[j]</tt> which are both equal and part of the longest common
  # subsequence, there will be some moment during the execution of
  # #traverse_sequences when arrow +a+ is pointing to <tt>A[i]</tt> and
  # arrow +b+ is pointing to <tt>B[j]</tt>. When this happens,
  # #traverse_sequences will call <tt>callbacks#match</tt> and then it will
  # advance both arrows.
  #
  # Otherwise, one of the arrows is pointing to an element of its sequence
  # that is not part of the longest common subsequence. #traverse_sequences
  # will advance that arrow and will call <tt>callbacks#discard_a</tt> or
  # <tt>callbacks#discard_b</tt>, depending on which arrow it advanced. If
  # both arrows point to elements that are not part of the longest common
  # subsequence, then #traverse_sequences will advance one of them and call
  # the appropriate callback, but it is not specified which it will call.
  #
  # The methods for <tt>callbacks#match</tt>, <tt>callbacks#discard_a</tt>,
  # and <tt>callbacks#discard_b</tt> are invoked with an event comprising
  # the action ("=", "+", or "-", respectively), the indicies +i+ and +j+,
  # and the elements <tt>A[i]</tt> and <tt>B[j]</tt>. Return values are
  # discarded by #traverse_sequences.
  #
  # === End of Sequences
  #
  # If arrow +a+ reaches the end of its sequence before arrow +b+ does,
  # #traverse_sequence will try to call <tt>callbacks#finished_a</tt> with
  # the last index and element of +A+ (<tt>A[-1]</tt>) and the current index
  # and element of +B+ (<tt>B[j]</tt>). If <tt>callbacks#finished_a</tt>
  # does not exist, then <tt>callbacks#discard_b</tt> will be called on each
  # element of +B+ until the end of the sequence is reached (the call will
  # be done with <tt>A[-1]</tt> and <tt>B[j]</tt> for each element).
  #
  # If +b+ reaches the end of +B+ before +a+ reaches the end of +A+,
  # <tt>callbacks#finished_b</tt> will be called with the current index and
  # element of +A+ (<tt>A[i]</tt>) and the last index and element of +B+
  # (<tt>A[-1]</tt>). Again, if <tt>callbacks#finished_b</tt> does not exist
  # on the callback object, then <tt>callbacks#discard_a</tt> will be called
  # on each element of +A+ until the end of the sequence is reached
  # (<tt>A[i]</tt> and <tt>B[-1]</tt>).
  #
  # There is a chance that one additional <tt>callbacks#discard_a</tt> or
  # <tt>callbacks#discard_b</tt> will be called after the end of the
  # sequence is reached, if +a+ has not yet reached the end of +A+ or +b+
  # has not yet reached the end of +B+.
  def traverse_sequences(seq1, seq2, callbacks = Diff::LCS::SequenceCallbacks, &block) #:yields change events:
    callbacks ||= Diff::LCS::SequenceCallbacks
    matches = Diff::LCS::Internals.lcs(seq1, seq2)

    run_finished_a = run_finished_b = false
    string = seq1.kind_of?(String)

    a_size = seq1.size
    b_size = seq2.size
    ai = bj = 0

    (0..matches.size).each do |i|
      b_line = matches[i]

      ax = string ? seq1[i, 1] : seq1[i]
      bx = string ? seq2[bj, 1] : seq2[bj]

      if b_line.nil?
        unless ax.nil? or (string and ax.empty?)
          event = Diff::LCS::ContextChange.new('-', i, ax, bj, bx)
          event = yield event if block_given?
          callbacks.discard_a(event)
        end
      else
        loop do
          break unless bj < b_line
          bx = string ? seq2[bj, 1] : seq2[bj]
          event = Diff::LCS::ContextChange.new('+', i, ax, bj, bx)
          event = yield event if block_given?
          callbacks.discard_b(event)
          bj += 1
        end
        bx = string ? seq2[bj, 1] : seq2[bj]
        event = Diff::LCS::ContextChange.new('=', i, ax, bj, bx)
        event = yield event if block_given?
        callbacks.match(event)
        bj += 1
      end
      ai = i
    end
    ai += 1

    # The last entry (if any) processed was a match. +ai+ and +bj+ point
    # just past the last matching lines in their sequences.
    while (ai < a_size) or (bj < b_size)
      # last A?
      if ai == a_size and bj < b_size
        if callbacks.respond_to?(:finished_a) and not run_finished_a
          ax = string ? seq1[-1, 1] : seq1[-1]
          bx = string ? seq2[bj, 1] : seq2[bj]
          event = Diff::LCS::ContextChange.new('>', (a_size - 1), ax, bj, bx)
          event = yield event if block_given?
          callbacks.finished_a(event)
          run_finished_a = true
        else
          ax = string ? seq1[ai, 1] : seq1[ai]
          loop do
            bx = string ? seq2[bj, 1] : seq2[bj]
            event = Diff::LCS::ContextChange.new('+', ai, ax, bj, bx)
            event = yield event if block_given?
            callbacks.discard_b(event)
            bj += 1
            break unless bj < b_size
          end
        end
      end

      # last B?
      if bj == b_size and ai < a_size
        if callbacks.respond_to?(:finished_b) and not run_finished_b
          ax = string ? seq1[ai, 1] : seq1[ai]
          bx = string ? seq2[-1, 1] : seq2[-1]
          event = Diff::LCS::ContextChange.new('<', ai, ax, (b_size - 1), bx)
          event = yield event if block_given?
          callbacks.finished_b(event)
          run_finished_b = true
        else
          bx = string ? seq2[bj, 1] : seq2[bj]
          loop do
            ax = string ? seq1[ai, 1] : seq1[ai]
            event = Diff::LCS::ContextChange.new('-', ai, ax, bj, bx)
            event = yield event if block_given?
            callbacks.discard_a(event)
            ai += 1
            break unless bj < b_size
          end
        end
      end

      if ai < a_size
        ax = string ? seq1[ai, 1] : seq1[ai]
        bx = string ? seq2[bj, 1] : seq2[bj]
        event = Diff::LCS::ContextChange.new('-', ai, ax, bj, bx)
        event = yield event if block_given?
        callbacks.discard_a(event)
        ai += 1
      end

      if bj < b_size
        ax = string ? seq1[ai, 1] : seq1[ai]
        bx = string ? seq2[bj, 1] : seq2[bj]
        event = Diff::LCS::ContextChange.new('+', ai, ax, bj, bx)
        event = yield event if block_given?
        callbacks.discard_b(event)
        bj += 1
      end
    end
  end

  # #traverse_balanced is an alternative to #traverse_sequences. It uses a
  # different algorithm to iterate through the entries in the computed
  # longest common subsequence. Instead of viewing the changes as insertions
  # or deletions from one of the sequences, #traverse_balanced will report
  # <em>changes</em> between the sequences.
  #
  # The arguments to #traverse_balanced are the two sequences to traverse
  # and a callback object, like this:
  #
  #   traverse_balanced(seq1, seq2, Diff::LCS::ContextDiffCallbacks.new)
  #
  # #sdiff is implemented with #traverse_balanced.
  #
  # == Callback Methods
  #
  # Optional callback methods are <em>emphasized</em>.
  #
  # callbacks#match::               Called when +a+ and +b+ are pointing to
  #                                 common elements in +A+ and +B+.
  # callbacks#discard_a::           Called when +a+ is pointing to an
  #                                 element not in +B+.
  # callbacks#discard_b::           Called when +b+ is pointing to an
  #                                 element not in +A+.
  # <em>callbacks#change</em>::     Called when +a+ and +b+ are pointing to
  #                                 the same relative position, but
  #                                 <tt>A[a]</tt> and <tt>B[b]</tt> are not
  #                                 the same; a <em>change</em> has
  #                                 occurred.
  #
  # #traverse_balanced might be a bit slower than #traverse_sequences,
  # noticable only while processing huge amounts of data.
  #
  # == Algorithm
  #
  #       a---+
  #           v
  #       A = a b c e h j l m n p
  #       B = b c d e f j k l m r s t
  #           ^
  #       b---+
  #
  # === Matches
  #
  # If there are two arrows (+a+ and +b+) pointing to elements of sequences
  # +A+ and +B+, the arrows will initially point to the first elements of
  # their respective sequences. #traverse_sequences will advance the arrows
  # through the sequences one element at a time, calling a method on the
  # user-specified callback object before each advance. It will advance the
  # arrows in such a way that if there are elements <tt>A[i]</tt> and
  # <tt>B[j]</tt> which are both equal and part of the longest common
  # subsequence, there will be some moment during the execution of
  # #traverse_sequences when arrow +a+ is pointing to <tt>A[i]</tt> and
  # arrow +b+ is pointing to <tt>B[j]</tt>. When this happens,
  # #traverse_sequences will call <tt>callbacks#match</tt> and then it will
  # advance both arrows.
  #
  # === Discards
  #
  # Otherwise, one of the arrows is pointing to an element of its sequence
  # that is not part of the longest common subsequence. #traverse_sequences
  # will advance that arrow and will call <tt>callbacks#discard_a</tt> or
  # <tt>callbacks#discard_b</tt>, depending on which arrow it advanced.
  #
  # === Changes
  #
  # If both +a+ and +b+ point to elements that are not part of the longest
  # common subsequence, then #traverse_sequences will try to call
  # <tt>callbacks#change</tt> and advance both arrows. If
  # <tt>callbacks#change</tt> is not implemented, then
  # <tt>callbacks#discard_a</tt> and <tt>callbacks#discard_b</tt> will be
  # called in turn.
  #
  # The methods for <tt>callbacks#match</tt>, <tt>callbacks#discard_a</tt>,
  # <tt>callbacks#discard_b</tt>, and <tt>callbacks#change</tt> are invoked
  # with an event comprising the action ("=", "+", "-", or "!",
  # respectively), the indicies +i+ and +j+, and the elements
  # <tt>A[i]</tt> and <tt>B[j]</tt>. Return values are discarded by
  # #traverse_balanced.
  #
  # === Context
  # Note that +i+ and +j+ may not be the same index position, even if +a+
  # and +b+ are considered to be pointing to matching or changed elements.
  def traverse_balanced(seq1, seq2, callbacks = Diff::LCS::BalancedCallbacks)
    matches = Diff::LCS::Internals.lcs(seq1, seq2)
    a_size = seq1.size
    b_size = seq2.size
    ai = bj = mb = 0
    ma = -1
    string = seq1.kind_of?(String)

    # Process all the lines in the match vector.
    loop do
      # Find next match indices +ma+ and +mb+
      loop do
        ma += 1
        break unless ma < matches.size and matches[ma].nil?
      end

      break if ma >= matches.size # end of matches?
      mb = matches[ma]

      # Change(seq2)
      while (ai < ma) or (bj < mb)
        ax = string ? seq1[ai, 1] : seq1[ai]
        bx = string ? seq2[bj, 1] : seq2[bj]

        case [(ai < ma), (bj < mb)]
        when [true, true]
          if callbacks.respond_to?(:change)
            event = Diff::LCS::ContextChange.new('!', ai, ax, bj, bx)
            event = yield event if block_given?
            callbacks.change(event)
            ai += 1
            bj += 1
          else
            event = Diff::LCS::ContextChange.new('-', ai, ax, bj, bx)
            event = yield event if block_given?
            callbacks.discard_a(event)
            ai += 1
            ax = string ? seq1[ai, 1] : seq1[ai]
            event = Diff::LCS::ContextChange.new('+', ai, ax, bj, bx)
            event = yield event if block_given?
            callbacks.discard_b(event)
            bj += 1
          end
        when [true, false]
          event = Diff::LCS::ContextChange.new('-', ai, ax, bj, bx)
          event = yield event if block_given?
          callbacks.discard_a(event)
          ai += 1
        when [false, true]
          event = Diff::LCS::ContextChange.new('+', ai, ax, bj, bx)
          event = yield event if block_given?
          callbacks.discard_b(event)
          bj += 1
        end
      end

      # Match
      ax = string ? seq1[ai, 1] : seq1[ai]
      bx = string ? seq2[bj, 1] : seq2[bj]
      event = Diff::LCS::ContextChange.new('=', ai, ax, bj, bx)
      event = yield event if block_given?
      callbacks.match(event)
      ai += 1
      bj += 1
    end

    while (ai < a_size) or (bj < b_size)
      ax = string ? seq1[ai, 1] : seq1[ai]
      bx = string ? seq2[bj, 1] : seq2[bj]

      case [(ai < a_size), (bj < b_size)]
      when [true, true]
        if callbacks.respond_to?(:change)
          event = Diff::LCS::ContextChange.new('!', ai, ax, bj, bx)
          event = yield event if block_given?
          callbacks.change(event)
          ai += 1
          bj += 1
        else
          event = Diff::LCS::ContextChange.new('-', ai, ax, bj, bx)
          event = yield event if block_given?
          callbacks.discard_a(event)
          ai += 1
          ax = string ? seq1[ai, 1] : seq1[ai]
          event = Diff::LCS::ContextChange.new('+', ai, ax, bj, bx)
          event = yield event if block_given?
          callbacks.discard_b(event)
          bj += 1
        end
      when [true, false]
        event = Diff::LCS::ContextChange.new('-', ai, ax, bj, bx)
        event = yield event if block_given?
        callbacks.discard_a(event)
        ai += 1
      when [false, true]
        event = Diff::LCS::ContextChange.new('+', ai, ax, bj, bx)
        event = yield event if block_given?
        callbacks.discard_b(event)
        bj += 1
      end
    end
  end

  PATCH_MAP = { #:nodoc:
    :patch => { '+' => '+', '-' => '-', '!' => '!', '=' => '=' },
    :unpatch => { '+' => '-', '-' => '+', '!' => '!', '=' => '=' }
  }

  # Applies a +patchset+ to the sequence +src+ according to the +direction+
  # (<tt>:patch</tt> or <tt>:unpatch</tt>), producing a new sequence.
  #
  # If the +direction+ is not specified, Diff::LCS::patch will attempt to
  # discover the direction of the +patchset+.
  #
  # A +patchset+ can be considered to apply forward (<tt>:patch</tt>) if the
  # following expression is true:
  #
  #     patch(s1, diff(s1, s2)) -> s2
  #
  # A +patchset+ can be considered to apply backward (<tt>:unpatch</tt>) if
  # the following expression is true:
  #
  #     patch(s2, diff(s1, s2)) -> s1
  #
  # If the +patchset+ contains no changes, the +src+ value will be returned
  # as either <tt>src.dup</tt> or +src+. A +patchset+ can be deemed as
  # having no changes if the following predicate returns true:
  #
  #     patchset.empty? or
  #       patchset.flatten.all? { |change| change.unchanged? }
  #
  # === Patchsets
  #
  # A +patchset+ is always an enumerable sequence of changes, hunks of
  # changes, or a mix of the two. A hunk of changes is an enumerable
  # sequence of changes:
  #
  #     [ # patchset
  #       # change
  #       [ # hunk
  #         # change
  #       ]
  #     ]
  #
  # The +patch+ method accepts <tt>patchset</tt>s that are enumerable
  # sequences containing either Diff::LCS::Change objects (or a subclass) or
  # the array representations of those objects. Prior to application, array
  # representations of Diff::LCS::Change objects will be reified.
  def patch(src, patchset, direction = nil)
    # Normalize the patchset.
    has_changes, patchset = Diff::LCS::Internals.analyze_patchset(patchset)

    if not has_changes
      return src.dup if src.respond_to? :dup
      return src
    end

    string = src.kind_of?(String)
    # Start with a new empty type of the source's class
    res = src.class.new

    direction ||= Diff::LCS::Internals.intuit_diff_direction(src, patchset)

    ai = bj = 0

    patch_map = PATCH_MAP[direction]

    patchset.flatten.each do |change|
      # Both Change and ContextChange support #action
      action = patch_map[change.action]

      case change
      when Diff::LCS::ContextChange
        case direction
        when :patch
          el = change.new_element
          op = change.old_position
          np = change.new_position
        when :unpatch
          el = change.old_element
          op = change.new_position
          np = change.old_position
        end

        case action
        when '-' # Remove details from the old string
          while ai < op
            res << (string ? src[ai, 1] : src[ai])
            ai += 1
            bj += 1
          end
          ai += 1
        when '+'
          while bj < np
            res << (string ? src[ai, 1] : src[ai])
            ai += 1
            bj += 1
          end

        res << el
        bj += 1
        when '='
          # This only appears in sdiff output with the SDiff callback.
          # Therefore, we only need to worry about dealing with a single
          # element.
          res << el

          ai += 1
          bj += 1
        when '!'
          while ai < op
            res << (string ? src[ai, 1] : src[ai])
            ai += 1
            bj += 1
          end

        bj += 1
        ai += 1

        res << el
        end
      when Diff::LCS::Change
        case action
        when '-'
          while ai < change.position
            res << (string ? src[ai, 1] : src[ai])
            ai += 1
            bj += 1
          end
          ai += 1
        when '+'
          while bj < change.position
            res << (string ? src[ai, 1] : src[ai])
            ai += 1
            bj += 1
          end

          bj += 1

          res << change.element
        end
      end
    end

    while ai < src.size
      res << (string ? src[ai, 1] : src[ai])
      ai += 1
      bj += 1
    end

    res
  end

  # Given a set of patchset, convert the current version to the prior
  # version. Does no auto-discovery.
  def unpatch!(src, patchset)
    patch(src, patchset, :unpatch)
  end

  # Given a set of patchset, convert the current version to the next
  # version. Does no auto-discovery.
  def patch!(src, patchset)
    patch(src, patchset, :patch)
  end
end
