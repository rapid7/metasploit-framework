# BufferedTokenizer takes a delimiter upon instantiation, or acts line-based
# by default.  It allows input to be spoon-fed from some outside source which
# receives arbitrary length datagrams which may-or-may-not contain the token
# by which entities are delimited.
#
# By default, new BufferedTokenizers will operate on lines delimited by "\n" by default
# or allow you to specify any delimiter token you so choose, which will then
# be used by String#split to tokenize the input data
#
# @example Using BufferedTokernizer to parse lines out of incoming data
#
#   module LineBufferedConnection
#     def receive_data(data)
#       (@buffer ||= BufferedTokenizer.new).extract(data).each do |line|
#         receive_line(line)
#       end
#     end
#   end
#
# @author Tony Arcieri
# @author Martin Emde
class BufferedTokenizer
  # @param [String] delimiter
  # @param [Integer] size_limit
  def initialize(delimiter = "\n", size_limit = nil)
    @delimiter  = delimiter
    @size_limit = size_limit

    # The input buffer is stored as an array.  This is by far the most efficient
    # approach given language constraints (in C a linked list would be a more
    # appropriate data structure).  Segments of input data are stored in a list
    # which is only joined when a token is reached, substantially reducing the
    # number of objects required for the operation.
    @input = []

    # Size of the input buffer
    @input_size = 0
  end

  # Extract takes an arbitrary string of input data and returns an array of
  # tokenized entities, provided there were any available to extract.
  #
  # @example
  #
  #   tokenizer.extract(data).
  #     map { |entity| Decode(entity) }.each { ... }
  #
  # @param [String] data
  def extract(data)
    # Extract token-delimited entities from the input string with the split command.
    # There's a bit of craftiness here with the -1 parameter.  Normally split would
    # behave no differently regardless of if the token lies at the very end of the
    # input buffer or not (i.e. a literal edge case)  Specifying -1 forces split to
    # return "" in this case, meaning that the last entry in the list represents a
    # new segment of data where the token has not been encountered
    entities = data.split @delimiter, -1

    # Check to see if the buffer has exceeded capacity, if we're imposing a limit
    if @size_limit
      raise 'input buffer full' if @input_size + entities.first.size > @size_limit
      @input_size += entities.first.size
    end

    # Move the first entry in the resulting array into the input buffer.  It represents
    # the last segment of a token-delimited entity unless it's the only entry in the list.
    @input << entities.shift

    # If the resulting array from the split is empty, the token was not encountered
    # (not even at the end of the buffer).  Since we've encountered no token-delimited
    # entities this go-around, return an empty array.
    return [] if entities.empty?

    # At this point, we've hit a token, or potentially multiple tokens.  Now we can bring
    # together all the data we've buffered from earlier calls without hitting a token,
    # and add it to our list of discovered entities.
    entities.unshift @input.join

    # Now that we've hit a token, joined the input buffer and added it to the entities
    # list, we can go ahead and clear the input buffer.  All of the segments that were
    # stored before the join can now be garbage collected.
    @input.clear

    # The last entity in the list is not token delimited, however, thanks to the -1
    # passed to split.  It represents the beginning of a new list of as-yet-untokenized
    # data, so we add it to the start of the list.
    @input << entities.pop

    # Set the new input buffer size, provided we're keeping track
    @input_size = @input.first.size if @size_limit

    # Now we're left with the list of extracted token-delimited entities we wanted
    # in the first place.  Hooray!
    entities
  end

  # Flush the contents of the input buffer, i.e. return the input buffer even though
  # a token has not yet been encountered.
  #
  # @return [String]
  def flush
    buffer = @input.join
    @input.clear
    buffer
  end

  # @return [Boolean]
  def empty?
    @input.empty?
  end
end
