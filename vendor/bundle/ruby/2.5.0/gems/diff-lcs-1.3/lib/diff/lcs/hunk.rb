# -*- ruby encoding: utf-8 -*-

require 'diff/lcs/block'

# A Hunk is a group of Blocks which overlap because of the context
# surrounding each block. (So if we're not using context, every hunk will
# contain one block.) Used in the diff program (bin/diff).
class Diff::LCS::Hunk
  # Create a hunk using references to both the old and new data, as well as
  # the piece of data.
  def initialize(data_old, data_new, piece, flag_context, file_length_difference)
    # At first, a hunk will have just one Block in it
    @blocks = [ Diff::LCS::Block.new(piece) ]
    if String.method_defined?(:encoding)
      @preferred_data_encoding = data_old.fetch(0, data_new.fetch(0,'') ).encoding
    end
    @data_old = data_old
    @data_new = data_new

    before = after = file_length_difference
    after += @blocks[0].diff_size
    @file_length_difference = after # The caller must get this manually

    # Save the start & end of each array. If the array doesn't exist (e.g.,
    # we're only adding items in this block), then figure out the line
    # number based on the line number of the other file and the current
    # difference in file lengths.
    if @blocks[0].remove.empty?
      a1 = a2 = nil
    else
      a1 = @blocks[0].remove[0].position
      a2 = @blocks[0].remove[-1].position
    end

    if @blocks[0].insert.empty?
      b1 = b2 = nil
    else
      b1 = @blocks[0].insert[0].position
      b2 = @blocks[0].insert[-1].position
    end

    @start_old = a1 || (b1 - before)
    @start_new = b1 || (a1 + before)
    @end_old   = a2 || (b2 - after)
    @end_new   = b2 || (a2 + after)

    self.flag_context = flag_context
  end

  attr_reader :blocks
  attr_reader :start_old, :start_new
  attr_reader :end_old, :end_new
  attr_reader :file_length_difference

  # Change the "start" and "end" fields to note that context should be added
  # to this hunk.
  attr_accessor :flag_context
  undef :flag_context=;
  def flag_context=(context) #:nodoc:
    return if context.nil? or context.zero?

    add_start = (context > @start_old) ? @start_old : context
    @start_old -= add_start
    @start_new -= add_start

    if (@end_old + context) > @data_old.size
      add_end = @data_old.size - @end_old
    else
      add_end = context
    end
    @end_old += add_end
    @end_new += add_end
  end

  # Merges this hunk and the provided hunk together if they overlap. Returns
  # a truthy value so that if there is no overlap, you can know the merge
  # was skipped.
  def merge(hunk)
    if overlaps?(hunk)
      @start_old = hunk.start_old
      @start_new = hunk.start_new
      blocks.unshift(*hunk.blocks)
    else
      nil
    end
  end
  alias_method :unshift, :merge

  # Determines whether there is an overlap between this hunk and the
  # provided hunk. This will be true if the difference between the two hunks
  # start or end positions is within one position of each other.
  def overlaps?(hunk)
    hunk and (((@start_old - hunk.end_old) <= 1) or
              ((@start_new - hunk.end_new) <= 1))
  end

  # Returns a diff string based on a format.
  def diff(format)
    case format
    when :old
      old_diff
    when :unified
      unified_diff
    when :context
      context_diff
    when :ed
      self
    when :reverse_ed, :ed_finish
      ed_diff(format)
    else
      raise "Unknown diff format #{format}."
    end
  end

  # Note that an old diff can't have any context. Therefore, we know that
  # there's only one block in the hunk.
  def old_diff
    warn "Expecting only one block in an old diff hunk!" if @blocks.size > 1
    op_act = { "+" => 'a', "-" => 'd', "!" => "c" }

    block = @blocks[0]

    # Calculate item number range. Old diff range is just like a context
    # diff range, except the ranges are on one line with the action between
    # them.
    s = encode("#{context_range(:old)}#{op_act[block.op]}#{context_range(:new)}\n")
    # If removing anything, just print out all the remove lines in the hunk
    # which is just all the remove lines in the block.
    @data_old[@start_old .. @end_old].each { |e| s << encode("< ") + e + encode("\n") } unless block.remove.empty?
    s << encode("---\n") if block.op == "!"
    @data_new[@start_new .. @end_new].each { |e| s << encode("> ") + e + encode("\n") } unless block.insert.empty?
    s
  end
  private :old_diff

  def unified_diff
    # Calculate item number range.
    s = encode("@@ -#{unified_range(:old)} +#{unified_range(:new)} @@\n")

    # Outlist starts containing the hunk of the old file. Removing an item
    # just means putting a '-' in front of it. Inserting an item requires
    # getting it from the new file and splicing it in. We splice in
    # +num_added+ items. Remove blocks use +num_added+ because splicing
    # changed the length of outlist.
    #
    # We remove +num_removed+ items. Insert blocks use +num_removed+
    # because their item numbers -- corresponding to positions in the NEW
    # file -- don't take removed items into account.
    lo, hi, num_added, num_removed = @start_old, @end_old, 0, 0

    outlist = @data_old[lo .. hi].map { |e| e.insert(0, encode(' ')) }

    @blocks.each do |block|
      block.remove.each do |item|
        op     = item.action.to_s # -
        offset = item.position - lo + num_added
        outlist[offset][0, 1] = encode(op)
        num_removed += 1
      end
      block.insert.each do |item|
        op     = item.action.to_s # +
        offset = item.position - @start_new + num_removed
        outlist[offset, 0] = encode(op) + @data_new[item.position]
        num_added += 1
      end
    end

    s << outlist.join(encode("\n"))
  end
  private :unified_diff

  def context_diff
    s = encode("***************\n")
    s << encode("*** #{context_range(:old)} ****\n")
    r = context_range(:new)

    # Print out file 1 part for each block in context diff format if there
    # are any blocks that remove items
    lo, hi = @start_old, @end_old
    removes = @blocks.select { |e| not e.remove.empty? }
    if removes
      outlist = @data_old[lo .. hi].map { |e| e.insert(0, encode(' ')) }

      removes.each do |block|
        block.remove.each do |item|
          outlist[item.position - lo][0, 1] = encode(block.op) # - or !
        end
      end
      s << outlist.join("\n")
    end

    s << encode("\n--- #{r} ----\n")
    lo, hi = @start_new, @end_new
    inserts = @blocks.select { |e| not e.insert.empty? }
    if inserts
      outlist = @data_new[lo .. hi].collect { |e| e.insert(0, encode(' ')) }
      inserts.each do |block|
        block.insert.each do |item|
          outlist[item.position - lo][0, 1] = encode(block.op) # + or !
        end
      end
      s << outlist.join("\n")
    end
    s
  end
  private :context_diff

  def ed_diff(format)
    op_act = { "+" => 'a', "-" => 'd', "!" => "c" }
    warn "Expecting only one block in an old diff hunk!" if @blocks.size > 1

    if format == :reverse_ed
      s = encode("#{op_act[@blocks[0].op]}#{context_range(:old)}\n")
    else
      s = encode("#{context_range(:old, ' ')}#{op_act[@blocks[0].op]}\n")
    end

    unless @blocks[0].insert.empty?
      @data_new[@start_new .. @end_new].each { |e| s << e + encode("\n") }
      s << encode(".\n")
    end
    s
  end
  private :ed_diff

  # Generate a range of item numbers to print. Only print 1 number if the
  # range has only one item in it. Otherwise, it's 'start,end'
  def context_range(mode, op = ',')
    case mode
    when :old
      s, e = (@start_old + 1), (@end_old + 1)
    when :new
      s, e = (@start_new + 1), (@end_new + 1)
    end

    (s < e) ? "#{s}#{op}#{e}" : "#{e}"
  end
  private :context_range

  # Generate a range of item numbers to print for unified diff. Print number
  # where block starts, followed by number of lines in the block
  # (don't print number of lines if it's 1)
  def unified_range(mode)
    case mode
    when :old
      s, e = (@start_old + 1), (@end_old + 1)
    when :new
      s, e = (@start_new + 1), (@end_new + 1)
    end

    length = e - s + 1
    first = (length < 2) ? e : s # "strange, but correct"
    (length == 1) ? "#{first}" : "#{first},#{length}"
  end
  private :unified_range

  if String.method_defined?(:encoding)
    def encode(literal, target_encoding = @preferred_data_encoding)
      literal.encode target_encoding
    end

    def encode_as(string, *args)
      args.map { |arg| arg.encode(string.encoding) }
    end
  else
    def encode(literal, target_encoding = nil)
      literal
    end
    def encode_as(string, *args)
      args
    end
  end

  private :encode
  private :encode_as
end
