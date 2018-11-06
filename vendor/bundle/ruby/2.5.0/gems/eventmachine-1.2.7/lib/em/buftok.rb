# BufferedTokenizer takes a delimiter upon instantiation, or acts line-based
# by default.  It allows input to be spoon-fed from some outside source which
# receives arbitrary length datagrams which may-or-may-not contain the token
# by which entities are delimited.  In this respect it's ideally paired with
# something like EventMachine (http://rubyeventmachine.com/).
class BufferedTokenizer
  # New BufferedTokenizers will operate on lines delimited by a delimiter,
  # which is by default the global input delimiter $/ ("\n").
  #
  # The input buffer is stored as an array.  This is by far the most efficient
  # approach given language constraints (in C a linked list would be a more
  # appropriate data structure).  Segments of input data are stored in a list
  # which is only joined when a token is reached, substantially reducing the
  # number of objects required for the operation.
  def initialize(delimiter = $/)
    @delimiter = delimiter
    @input = []
    @tail = ''
    @trim = @delimiter.length - 1
  end

  # Extract takes an arbitrary string of input data and returns an array of
  # tokenized entities, provided there were any available to extract.  This
  # makes for easy processing of datagrams using a pattern like:
  #
  #   tokenizer.extract(data).map { |entity| Decode(entity) }.each do ...
  #
  # Using -1 makes split to return "" if the token is at the end of
  # the string, meaning the last element is the start of the next chunk.
  def extract(data)
    if @trim > 0
      tail_end = @tail.slice!(-@trim, @trim) # returns nil if string is too short
      data = tail_end + data if tail_end
    end

    @input << @tail
    entities = data.split(@delimiter, -1)
    @tail = entities.shift

    unless entities.empty?
      @input << @tail
      entities.unshift @input.join
      @input.clear
      @tail = entities.pop
    end

    entities
  end

  # Flush the contents of the input buffer, i.e. return the input buffer even though
  # a token has not yet been encountered
  def flush
    @input << @tail
    buffer = @input.join
    @input.clear
    @tail = "" # @tail.clear is slightly faster, but not supported on 1.8.7
    buffer
  end
end
