# -*- ruby encoding: utf-8 -*-

module Diff
  # = Diff::LCS 1.1.3
  # Computes "intelligent" differences between two sequenced Enumerables.
  # This is an implementation of the McIlroy-Hunt "diff" algorithm for
  # Enumerable objects that include Diffable.
  #
  # Based on Mario I. Wolczko's Smalltalk version (1.2, 1993) and Ned Konz's
  # Perl version (Algorithm::Diff 1.15).
  #
  # == Synopsis
  #   require 'diff/lcs'
  #
  #   seq1 = %w(a b c e h j l m n p)
  #   seq2 = %w(b c d e f j k l m r s t)
  #
  #   lcs = Diff::LCS.LCS(seq1, seq2)
  #   diffs = Diff::LCS.diff(seq1, seq2)
  #   sdiff = Diff::LCS.sdiff(seq1, seq2)
  #   seq = Diff::LCS.traverse_sequences(seq1, seq2, callback_obj)
  #   bal = Diff::LCS.traverse_balanced(seq1, seq2, callback_obj)
  #   seq2 == Diff::LCS.patch(seq1, diffs)
  #   seq2 == Diff::LCS.patch!(seq1, diffs)
  #   seq1 == Diff::LCS.unpatch(seq2, diffs)
  #   seq1 == Diff::LCS.unpatch!(seq2, diffs)
  #   seq2 == Diff::LCS.patch(seq1, sdiff)
  #   seq2 == Diff::LCS.patch!(seq1, sdiff)
  #   seq1 == Diff::LCS.unpatch(seq2, sdiff)
  #   seq1 == Diff::LCS.unpatch!(seq2, sdiff)
  #
  # Alternatively, objects can be extended with Diff::LCS:
  #
  #   seq1.extend(Diff::LCS)
  #   lcs = seq1.lcs(seq2)
  #   diffs = seq1.diff(seq2)
  #   sdiff = seq1.sdiff(seq2)
  #   seq = seq1.traverse_sequences(seq2, callback_obj)
  #   bal = seq1.traverse_balanced(seq2, callback_obj)
  #   seq2 == seq1.patch(diffs)
  #   seq2 == seq1.patch!(diffs)
  #   seq1 == seq2.unpatch(diffs)
  #   seq1 == seq2.unpatch!(diffs)
  #   seq2 == seq1.patch(sdiff)
  #   seq2 == seq1.patch!(sdiff)
  #   seq1 == seq2.unpatch(sdiff)
  #   seq1 == seq2.unpatch!(sdiff)
  # 
  # Default extensions are provided for Array and String objects through the
  # use of 'diff/lcs/array' and 'diff/lcs/string'.
  #
  # == Introduction (by Mark-Jason Dominus)
  # 
  # <em>The following text is from the Perl documentation. The only changes
  # have been to make the text appear better in Rdoc</em>.
  #
  # I once read an article written by the authors of +diff+; they said that
  # they hard worked very hard on the algorithm until they found the right
  # one.
  #
  # I think what they ended up using (and I hope someone will correct me,
  # because I am not very confident about this) was the `longest common
  # subsequence' method. In the LCS problem, you have two sequences of
  # items:
  #
  #    a b c d f g h j q z
  #    a b c d e f g i j k r x y z
  #
  # and you want to find the longest sequence of items that is present in
  # both original sequences in the same order. That is, you want to find a
  # new sequence *S* which can be obtained from the first sequence by
  # deleting some items, and from the second sequence by deleting other
  # items. You also want *S* to be as long as possible. In this case *S* is:
  # 
  #    a b c d f g j z
  #
  # From there it's only a small step to get diff-like output:
  #
  #    e   h i   k   q r x y
  #    +   - +   +   - + + +
  #
  # This module solves the LCS problem. It also includes a canned function
  # to generate +diff+-like output.
  #
  # It might seem from the example above that the LCS of two sequences is
  # always pretty obvious, but that's not always the case, especially when
  # the two sequences have many repeated elements. For example, consider
  #
  #    a x b y c z p d q
  #    a b c a x b y c z
  #
  # A naive approach might start by matching up the +a+ and +b+ that appear
  # at the beginning of each sequence, like this:
  # 
  #    a x b y c         z p d q
  #    a   b   c a b y c z
  #
  # This finds the common subsequence +a b c z+. But actually, the LCS is
  # +a x b y c z+:
  #
  #          a x b y c z p d q
  #    a b c a x b y c z
  #
  # == Author
  # This version is by Austin Ziegler <austin@rubyforge.org>.
  #
  # It is based on the Perl Algorithm::Diff (1.15) by Ned Konz , copyright
  # &copy; 2000&ndash;2002 and the Smalltalk diff version by Mario I.
  # Wolczko, copyright &copy; 1993. Documentation includes work by
  # Mark-Jason Dominus.
  #
  # == Licence
  # Copyright &copy; 2004 Austin Ziegler
  # This program is free software; you can redistribute it and/or modify it
  # under the same terms as Ruby, or alternatively under the Perl Artistic
  # licence.
  #
  # == Credits
  # Much of the documentation is taken directly from the Perl
  # Algorithm::Diff implementation and was written originally by Mark-Jason
  # Dominus and later by Ned Konz. The basic Ruby implementation was
  # re-ported from the Smalltalk implementation, available at
  # ftp://st.cs.uiuc.edu/pub/Smalltalk/MANCHESTER/manchester/4.0/diff.st
  #
  # #sdiff and #traverse_balanced were written for the Perl version by Mike
  # Schilli <m@perlmeister.com>.
  #
  # "The algorithm is described in <em>A Fast Algorithm for Computing
  # Longest Common Subsequences</em>, CACM, vol.20, no.5, pp.350-353, May
  # 1977, with a few minor improvements to improve the speed."
  module LCS
    VERSION = '1.1.3'
  end
end

require 'diff/lcs/callbacks'

module Diff::LCS
  # Returns an Array containing the longest common subsequence(s) between
  # +self+ and +other+. See Diff::LCS#LCS.
  #
  #   lcs = seq1.lcs(seq2)
  def lcs(other, &block) #:yields self[ii] if there are matched subsequences:
    Diff::LCS.LCS(self, other, &block)
  end

  # Returns the difference set between +self+ and +other+. See
  # Diff::LCS#diff.
  def diff(other, callbacks = nil, &block)
    Diff::LCS::diff(self, other, callbacks, &block)
  end

  # Returns the balanced ("side-by-side") difference set between +self+ and
  # +other+. See Diff::LCS#sdiff.
  def sdiff(other, callbacks = nil, &block)
    Diff::LCS::sdiff(self, other, callbacks, &block)
  end

  # Traverses the discovered longest common subsequences between +self+ and
  # +other+. See Diff::LCS#traverse_sequences.
  def traverse_sequences(other, callbacks = nil, &block)
    traverse_sequences(self, other, callbacks ||
                       Diff::LCS::YieldingCallbacks, &block)
  end

  # Traverses the discovered longest common subsequences between +self+ and
  # +other+ using the alternate, balanced algorithm. See
  # Diff::LCS#traverse_balanced.
  def traverse_balanced(other, callbacks = nil, &block)
    traverse_balanced(self, other, callbacks ||
                      Diff::LCS::YieldingCallbacks, &block)
  end

  # Attempts to patch a copy of +self+ with the provided +patchset+. See
  # Diff::LCS#patch.
  def patch(patchset)
    Diff::LCS::patch(self.dup, patchset)
  end

  # Attempts to unpatch a copy of +self+ with the provided +patchset+. See
  # Diff::LCS#patch.
  def unpatch(patchset)
    Diff::LCS::unpatch(self.dup, patchset)
  end

  # Attempts to patch +self+ with the provided +patchset+. See
  # Diff::LCS#patch!. Does no autodiscovery.
  def patch!(patchset)
    Diff::LCS::patch!(self, patchset)
  end

  # Attempts to unpatch +self+ with the provided +patchset+. See
  # Diff::LCS#unpatch. Does no autodiscovery.
  def unpatch!(patchset)
    Diff::LCS::unpatch!(self, patchset)
  end
end

module Diff::LCS
  class << self
    # Given two sequenced Enumerables, LCS returns an Array containing their
    # longest common subsequences.
    #
    #   lcs = Diff::LCS.LCS(seq1, seq2)
    #
    # This array whose contents is such that:
    #
    #   lcs.each_with_index do |ee, ii|
    #     assert(ee.nil? || (seq1[ii] == seq2[ee]))
    #   end
    #
    # If a block is provided, the matching subsequences will be yielded from
    # +seq1+ in turn and may be modified before they are placed into the
    # returned Array of subsequences.
    def LCS(seq1, seq2, &block) #:yields seq1[ii] for each matched:
      matches = Diff::LCS.__lcs(seq1, seq2)
      ret = []
      matches.each_with_index do |ee, ii|
        unless matches[ii].nil?
          if block_given?
            ret << (yield seq1[ii])
          else
            ret << seq1[ii]
          end
        end
      end
      ret
    end

    # Diff::LCS.diff computes the smallest set of additions and deletions
    # necessary to turn the first sequence into the second, and returns a
    # description of these changes.
    # 
    # See Diff::LCS::DiffCallbacks for the default behaviour. An alternate
    # behaviour may be implemented with Diff::LCS::ContextDiffCallbacks. If
    # a Class argument is provided for +callbacks+, #diff will attempt to
    # initialise it. If the +callbacks+ object (possibly initialised)
    # responds to #finish, it will be called.
    def diff(seq1, seq2, callbacks = nil, &block) # :yields diff changes:
      callbacks ||= Diff::LCS::DiffCallbacks
      if callbacks.kind_of?(Class)
        cb = callbacks.new rescue callbacks
        callbacks = cb
      end
      traverse_sequences(seq1, seq2, callbacks)
      callbacks.finish if callbacks.respond_to?(:finish)

      if block_given?
        res = callbacks.diffs.map do |hunk|
          if hunk.kind_of?(Array)
            hunk = hunk.map { |hunk_block| yield hunk_block }
          else
            yield hunk
          end
        end
        res
      else
        callbacks.diffs
      end
    end

    # Diff::LCS.sdiff computes all necessary components to show two sequences
    # and their minimized differences side by side, just like the Unix
    # utility <em>sdiff</em> does:
    #
    #     old        <     -
    #     same             same
    #     before     |     after
    #     -          >     new
    #
    # See Diff::LCS::SDiffCallbacks for the default behaviour. An alternate
    # behaviour may be implemented with Diff::LCS::ContextDiffCallbacks. If
    # a Class argument is provided for +callbacks+, #diff will attempt to
    # initialise it. If the +callbacks+ object (possibly initialised)
    # responds to #finish, it will be called.
    def sdiff(seq1, seq2, callbacks = nil, &block) #:yields diff changes:
      callbacks ||= Diff::LCS::SDiffCallbacks
      if callbacks.kind_of?(Class)
        cb = callbacks.new rescue callbacks
        callbacks = cb
      end
      traverse_balanced(seq1, seq2, callbacks)
      callbacks.finish if callbacks.respond_to?(:finish)

      if block_given?
        res = callbacks.diffs.map do |hunk|
          if hunk.kind_of?(Array)
            hunk = hunk.map { |hunk_block| yield hunk_block }
          else
            yield hunk
          end
        end
        res
      else
        callbacks.diffs
      end
    end

    # Diff::LCS.traverse_sequences is the most general facility provided by this
    # module; +diff+ and +LCS+ are implemented as calls to it.
    #
    # The arguments to #traverse_sequences are the two sequences to
    # traverse, and a callback object, like this:
    #
    #   traverse_sequences(seq1, seq2, Diff::LCS::ContextDiffCallbacks.new)
    #
    # #diff is implemented with #traverse_sequences.
    #
    # == Callback Methods
    # Optional callback methods are <em>emphasized</em>.
    #
    # callbacks#match::               Called when +a+ and +b+ are pointing
    #                                 to common elements in +A+ and +B+.
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
    #       a---+
    #           v
    #       A = a b c e h j l m n p
    #       B = b c d e f j k l m r s t
    #           ^
    #       b---+
    #
    # If there are two arrows (+a+ and +b+) pointing to elements of
    # sequences +A+ and +B+, the arrows will initially point to the first
    # elements of their respective sequences. #traverse_sequences will
    # advance the arrows through the sequences one element at a time,
    # calling a method on the user-specified callback object before each
    # advance. It will advance the arrows in such a way that if there are
    # elements <tt>A[ii]</tt> and <tt>B[jj]</tt> which are both equal and
    # part of the longest common subsequence, there will be some moment
    # during the execution of #traverse_sequences when arrow +a+ is pointing
    # to <tt>A[ii]</tt> and arrow +b+ is pointing to <tt>B[jj]</tt>. When
    # this happens, #traverse_sequences will call <tt>callbacks#match</tt>
    # and then it will advance both arrows.
    #
    # Otherwise, one of the arrows is pointing to an element of its sequence
    # that is not part of the longest common subsequence.
    # #traverse_sequences will advance that arrow and will call
    # <tt>callbacks#discard_a</tt> or <tt>callbacks#discard_b</tt>, depending
    # on which arrow it advanced. If both arrows point to elements that are
    # not part of the longest common subsequence, then #traverse_sequences
    # will advance one of them and call the appropriate callback, but it is
    # not specified which it will call.
    #
    # The methods for <tt>callbacks#match</tt>, <tt>callbacks#discard_a</tt>,
    # and <tt>callbacks#discard_b</tt> are invoked with an event comprising
    # the action ("=", "+", or "-", respectively), the indicies +ii+ and
    # +jj+, and the elements <tt>A[ii]</tt> and <tt>B[jj]</tt>. Return
    # values are discarded by #traverse_sequences.
    #
    # === End of Sequences
    # If arrow +a+ reaches the end of its sequence before arrow +b+ does,
    # #traverse_sequence will try to call <tt>callbacks#finished_a</tt> with
    # the last index and element of +A+ (<tt>A[-1]</tt>) and the current
    # index and element of +B+ (<tt>B[jj]</tt>). If
    # <tt>callbacks#finished_a</tt> does not exist, then
    # <tt>callbacks#discard_b</tt> will be called on each element of +B+
    # until the end of the sequence is reached (the call
    # will be done with <tt>A[-1]</tt> and <tt>B[jj]</tt> for each element).
    #
    # If +b+ reaches the end of +B+ before +a+ reaches the end of +A+,
    # <tt>callbacks#finished_b</tt> will be called with the current index
    # and element of +A+ (<tt>A[ii]</tt>) and the last index and element of
    # +B+ (<tt>A[-1]</tt>). Again, if <tt>callbacks#finished_b</tt> does not
    # exist on the callback object, then <tt>callbacks#discard_a</tt> will
    # be called on each element of +A+ until the end of the sequence is
    # reached (<tt>A[ii]</tt> and <tt>B[-1]</tt>).
    #
    # There is a chance that one additional <tt>callbacks#discard_a</tt> or
    # <tt>callbacks#discard_b</tt> will be called after the end of the
    # sequence is reached, if +a+ has not yet reached the end of +A+ or +b+
    # has not yet reached the end of +B+.
    def traverse_sequences(seq1, seq2, callbacks = Diff::LCS::SequenceCallbacks, &block) #:yields change events:
      matches = Diff::LCS.__lcs(seq1, seq2)

      run_finished_a = run_finished_b = false
      string = seq1.kind_of?(String)

      a_size = seq1.size
      b_size = seq2.size
      ai = bj = 0

      (0 .. matches.size).each do |ii|
        b_line = matches[ii]

        ax = string ? seq1[ii, 1] : seq1[ii]
        bx = string ? seq2[bj, 1] : seq2[bj]

        if b_line.nil?
          unless ax.nil?
            event = Diff::LCS::ContextChange.new('-', ii, ax, bj, bx)
            event = yield event if block_given?
            callbacks.discard_a(event)
          end
        else
          loop do
            break unless bj < b_line
            bx = string ? seq2[bj, 1] : seq2[bj]
            event = Diff::LCS::ContextChange.new('+', ii, ax, bj, bx)
            event = yield event if block_given?
            callbacks.discard_b(event)
            bj += 1
          end
          bx = string ? seq2[bj, 1] : seq2[bj]
          event = Diff::LCS::ContextChange.new('=', ii, ax, bj, bx)
          event = yield event if block_given?
          callbacks.match(event)
          bj += 1
        end
        ai = ii
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

    # #traverse_balanced is an alternative to #traverse_sequences. It
    # uses a different algorithm to iterate through the entries in the
    # computed longest common subsequence. Instead of viewing the changes as
    # insertions or deletions from one of the sequences, #traverse_balanced
    # will report <em>changes</em> between the sequences. To represent a
    #
    # The arguments to #traverse_balanced are the two sequences to traverse
    # and a callback object, like this:
    #
    #   traverse_balanced(seq1, seq2, Diff::LCS::ContextDiffCallbacks.new)
    #
    # #sdiff is implemented with #traverse_balanced.
    #
    # == Callback Methods
    # Optional callback methods are <em>emphasized</em>.
    #
    # callbacks#match::               Called when +a+ and +b+ are pointing
    #                                 to common elements in +A+ and +B+.
    # callbacks#discard_a::           Called when +a+ is pointing to an
    #                                 element not in +B+.
    # callbacks#discard_b::           Called when +b+ is pointing to an
    #                                 element not in +A+.
    # <em>callbacks#change</em>::     Called when +a+ and +b+ are pointing
    #                                 to the same relative position, but
    #                                 <tt>A[a]</tt> and <tt>B[b]</tt> are
    #                                 not the same; a <em>change</em> has
    #                                 occurred.
    #
    # #traverse_balanced might be a bit slower than #traverse_sequences,
    # noticable only while processing huge amounts of data.
    #
    # The +sdiff+ function of this module is implemented as call to
    # #traverse_balanced.
    #
    # == Algorithm
    #       a---+
    #           v
    #       A = a b c e h j l m n p
    #       B = b c d e f j k l m r s t
    #           ^
    #       b---+
    #
    # === Matches
    # If there are two arrows (+a+ and +b+) pointing to elements of
    # sequences +A+ and +B+, the arrows will initially point to the first
    # elements of their respective sequences. #traverse_sequences will
    # advance the arrows through the sequences one element at a time,
    # calling a method on the user-specified callback object before each
    # advance. It will advance the arrows in such a way that if there are
    # elements <tt>A[ii]</tt> and <tt>B[jj]</tt> which are both equal and
    # part of the longest common subsequence, there will be some moment
    # during the execution of #traverse_sequences when arrow +a+ is pointing
    # to <tt>A[ii]</tt> and arrow +b+ is pointing to <tt>B[jj]</tt>. When
    # this happens, #traverse_sequences will call <tt>callbacks#match</tt>
    # and then it will advance both arrows.
    #
    # === Discards
    # Otherwise, one of the arrows is pointing to an element of its sequence
    # that is not part of the longest common subsequence.
    # #traverse_sequences will advance that arrow and will call
    # <tt>callbacks#discard_a</tt> or <tt>callbacks#discard_b</tt>,
    # depending on which arrow it advanced.
    #
    # === Changes
    # If both +a+ and +b+ point to elements that are not part of the longest
    # common subsequence, then #traverse_sequences will try to call
    # <tt>callbacks#change</tt> and advance both arrows. If
    # <tt>callbacks#change</tt> is not implemented, then
    # <tt>callbacks#discard_a</tt> and <tt>callbacks#discard_b</tt> will be
    # called in turn.
    #
    # The methods for <tt>callbacks#match</tt>, <tt>callbacks#discard_a</tt>,
    # <tt>callbacks#discard_b</tt>, and <tt>callbacks#change</tt> are
    # invoked with an event comprising the action ("=", "+", "-", or "!",
    # respectively), the indicies +ii+ and +jj+, and the elements
    # <tt>A[ii]</tt> and <tt>B[jj]</tt>. Return values are discarded by
    # #traverse_balanced.
    #
    # === Context
    # Note that +ii+ and +jj+ may not be the same index position, even if
    # +a+ and +b+ are considered to be pointing to matching or changed
    # elements.
    def traverse_balanced(seq1, seq2, callbacks = Diff::LCS::BalancedCallbacks)
      matches = Diff::LCS.__lcs(seq1, seq2)
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

    # Given a patchset, convert the current version to the new
    # version. If +direction+ is not specified (must be
    # <tt>:patch</tt> or <tt>:unpatch</tt>), then discovery of the
    # direction of the patch will be attempted.
    def patch(src, patchset, direction = nil)
      string = src.kind_of?(String)
        # Start with a new empty type of the source's class
      res = src.class.new

        # Normalize the patchset.
      patchset = __normalize_patchset(patchset)

      direction ||= Diff::LCS.__diff_direction(src, patchset)
      direction ||= :patch

      ai = bj = 0

      patchset.each do |change|
          # Both Change and ContextChange support #action
        action = PATCH_MAP[direction][change.action]

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
      Diff::LCS.patch(src, patchset, :unpatch)
    end

    # Given a set of patchset, convert the current version to the next
    # version. Does no auto-discovery.
    def patch!(src, patchset)
      Diff::LCS.patch(src, patchset, :patch)
    end

# private
    # Compute the longest common subsequence between the sequenced
    # Enumerables +a+ and +b+. The result is an array whose contents is such
    # that
    #
    #     result = Diff::LCS.__lcs(a, b)
    #     result.each_with_index do |e, ii|
    #       assert_equal(a[ii], b[e]) unless e.nil?
    #     end
    #
    # Note: This will be deprecated as a public function in a future release.
    def __lcs(a, b)
      a_start = b_start = 0
      a_finish = a.size - 1
      b_finish = b.size - 1
      vector = []

      # Prune off any common elements at the beginning...
      while (a_start <= a_finish) and
        (b_start <= b_finish) and
        (a[a_start] == b[b_start])
        vector[a_start] = b_start
        a_start += 1
        b_start += 1
      end

      # Now the end...
      while (a_start <= a_finish) and
        (b_start <= b_finish) and
        (a[a_finish] == b[b_finish])
        vector[a_finish] = b_finish
        a_finish -= 1
        b_finish -= 1
      end

      # Now, compute the equivalence classes of positions of elements.
      b_matches = Diff::LCS.__position_hash(b, b_start .. b_finish)

      thresh = []
      links = []

      (a_start .. a_finish).each do |ii|
        ai = a.kind_of?(String) ? a[ii, 1] : a[ii]
        bm = b_matches[ai]
        kk = nil
        bm.reverse_each do |jj|
          if kk and (thresh[kk] > jj) and (thresh[kk - 1] < jj)
            thresh[kk] = jj
          else
            kk = Diff::LCS.__replace_next_larger(thresh, jj, kk)
          end
          links[kk] = [ (kk > 0) ? links[kk - 1] : nil, ii, jj ] unless kk.nil?
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

    # Find the place at which +value+ would normally be inserted into the
    # Enumerable. If that place is already occupied by +value+, do nothing
    # and return +nil+. If the place does not exist (i.e., it is off the end
    # of the Enumerable), add it to the end. Otherwise, replace the element
    # at that point with +value+. It is assumed that the Enumerable's values
    # are numeric.
    #
    # This operation preserves the sort order.
    #
    # Note: This will be deprecated as a public function in a future release.
    def __replace_next_larger(enum, value, last_index = nil)
        # Off the end?
      if enum.empty? or (value > enum[-1])
        enum << value
        return enum.size - 1
      end

        # Binary search for the insertion point
      last_index ||= enum.size
      first_index = 0
      while (first_index <= last_index)
        ii = (first_index + last_index) >> 1

        found = enum[ii]

        if value == found
          return nil
        elsif value > found
          first_index = ii + 1
        else
          last_index = ii - 1
        end
      end

        # The insertion point is in first_index; overwrite the next larger
        # value.
      enum[first_index] = value
      return first_index
    end

    # If +vector+ maps the matching elements of another collection onto this
    # Enumerable, compute the inverse +vector+ that maps this Enumerable
    # onto the collection. (Currently unused.)
    #
    # Note: This will be deprecated as a public function in a future release.
    def __inverse_vector(a, vector)
      inverse = a.dup
      (0 ... vector.size).each do |ii|
        inverse[vector[ii]] = ii unless vector[ii].nil?
      end
      inverse
    end

    # Returns a hash mapping each element of an Enumerable to the set of
    # positions it occupies in the Enumerable, optionally restricted to the
    # elements specified in the range of indexes specified by +interval+.
    #
    # Note: This will be deprecated as a public function in a future release.
    def __position_hash(enum, interval = 0 .. -1)
      hash = Hash.new { |hh, kk| hh[kk] = [] }
      interval.each do |ii|
        kk = enum.kind_of?(String) ? enum[ii, 1] : enum[ii]
        hash[kk] << ii
      end
      hash
    end

    # Examine the patchset and the source to see in which direction the
    # patch should be applied.
    #
    # WARNING: By default, this examines the whole patch, so this could take
    # some time. This also works better with Diff::LCS::ContextChange or
    # Diff::LCS::Change as its source, as an array will cause the creation
    # of one of the above.
    #
    # Note: This will be deprecated as a public function in a future release.
    def __diff_direction(src, patchset, limit = nil)
      count = left = left_miss = right = right_miss = 0
      string = src.kind_of?(String)

      patchset.each do |change|
        count += 1

        case change
        when Diff::LCS::Change
          # With a simplistic change, we can't tell the difference between
          # the left and right on '!' actions, so we ignore those. On '='
          # actions, if there's a miss, we miss both left and right.
          element = string ? src[change.position, 1] : src[change.position]

          case change.action
          when '-'
            if element == change.element
              left += 1
            else
              left_miss += 1
            end
          when '+'
            if element == change.element
              right += 1
            else
              right_miss += 1
            end
          when '='
            if element != change.element
              left_miss += 1
              right_miss += 1
            end
          end
        when Diff::LCS::ContextChange
          case change.action
          when '-' # Remove details from the old string
            element = string ? src[change.old_position, 1] : src[change.old_position]
            if element == change.old_element
              left += 1
            else
              left_miss += 1
            end
          when '+'
            element = string ? src[change.new_position, 1] : src[change.new_position]
            if element == change.new_element
              right += 1
            else
              right_miss += 1
            end
          when '='
            le = string ? src[change.old_position, 1] : src[change.old_position]
            re = string ? src[change.new_position, 1] : src[change.new_position]

            left_miss += 1 if le != change.old_element
            right_miss += 1 if re != change.new_element
          when '!'
            element = string ? src[change.old_position, 1] : src[change.old_position]
            if element == change.old_element
              left += 1
            else
              element = string ? src[change.new_position, 1] : src[change.new_position]
              if element == change.new_element
                right += 1
              else
                left_miss += 1
                right_miss += 1
              end
            end
          end
        end

        break if (not limit.nil?) && (count > limit)
      end

      no_left = (left == 0) and (left_miss >= 0)
      no_right = (right == 0) and (right_miss >= 0)

      case [no_left, no_right]
      when [false, true]
        return :patch
      when [true, false]
        return :unpatch
      else
        raise "The provided patchset does not appear to apply to the provided value as either source or destination value."
      end
    end

    # Normalize the patchset. A patchset is always a sequence of changes, but
    # how those changes are represented may vary, depending on how they were
    # generated. In all cases we support, we also support the array
    # representation of the changes. The formats are:
    #
    #   [ # patchset <- Diff::LCS.diff(a, b)
    #     [ # one or more hunks
    #       Diff::LCS::Change # one or more changes
    #     ] ]
    #
    #   [ # patchset, equivalent to the above
    #     [ # one or more hunks
    #       [ action, line, value ] # one or more changes
    #     ] ]
    #
    #   [ # patchset <- Diff::LCS.diff(a, b, Diff::LCS::ContextDiffCallbacks)
    #     #       OR <- Diff::LCS.sdiff(a, b, Diff::LCS::ContextDiffCallbacks)
    #     [ # one or more hunks
    #       Diff::LCS::ContextChange # one or more changes
    #     ] ]
    #
    #   [ # patchset, equivalent to the above
    #     [ # one or more hunks
    #       [ action, [ old line, old value ], [ new line, new value ] ]
    #         # one or more changes
    #     ] ]
    #
    #   [ # patchset <- Diff::LCS.sdiff(a, b)
    #     #       OR <- Diff::LCS.diff(a, b, Diff::LCS::SDiffCallbacks)
    #     Diff::LCS::ContextChange # one or more changes
    #   ]
    #
    #   [ # patchset, equivalent to the above
    #     [ action, [ old line, old value ], [ new line, new value ] ]
    #       # one or more changes
    #   ]
    #
    # The result of this will be either of the following.
    #
    #   [ # patchset
    #     Diff::LCS::ContextChange # one or more changes
    #   ]
    #
    #   [ # patchset
    #     Diff::LCS::Change # one or more changes
    #   ]
    #
    # If either of the above is provided, it will be returned as such.
    #
    # Note: This will be deprecated as a public function in a future release.
    def __normalize_patchset(patchset)
      patchset.map do |hunk|
        case hunk
        when Diff::LCS::ContextChange, Diff::LCS::Change
          hunk
        when Array
          if (not hunk[0].kind_of?(Array)) and hunk[1].kind_of?(Array) and hunk[2].kind_of?(Array)
            Diff::LCS::ContextChange.from_a(hunk)
          else
            hunk.map do |change|
              case change
              when Diff::LCS::ContextChange, Diff::LCS::Change
                change
              when Array
                  # change[1] will ONLY be an array in a ContextChange#to_a call.
                  # In Change#to_a, it represents the line (singular).
                if change[1].kind_of?(Array)
                  Diff::LCS::ContextChange.from_a(change)
                else
                  Diff::LCS::Change.from_a(change)
                end
              end
            end
          end
        else
          raise ArgumentError, "Cannot normalise a hunk of class #{hunk.class}."
        end
      end.flatten
    end
  end
end

# vim: ft=ruby
