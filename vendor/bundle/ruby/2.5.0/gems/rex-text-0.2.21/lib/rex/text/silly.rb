# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Converts a string to one similar to what would be used by cowsay(1), a UNIX utility for
    # displaying text as if it was coming from an ASCII-cow's mouth:
    #
    #       __________________
    #      < the cow says moo >
    #       ------------------
    #              \   ^__^
    #               \  (oo)\_______
    #                  (__)\       )\/\
    #                      ||----w |
    #                      ||     ||
    #
    # @param text [String] The string to cowsay
    # @param width [Integer] Width of the cow's cloud.  Default's to cowsay(1)'s default, 39.
    def self.cowsay(text, width=39)
      # cowsay(1) chunks a message up into 39-byte chunks and wraps it in '| ' and ' |'
      # Rex::Text.wordwrap(text, 0, 39, ' |', '| ') almost does this, but won't
      # split a word that has > 39 characters in it which results in oddly formed
      # text in the cowsay banner, so just do it by hand.  This big mess wraps
      # the provided text in an ASCII-cloud and then makes it look like the cloud
      # is a thought/word coming from the ASCII-cow.  Each line in the
      # ASCII-cloud is no more than the specified number-characters long, and the
      # cloud corners are made to look rounded
      text_lines = text.scan(Regexp.new(".{1,#{width-4}}"))
      max_length = text_lines.map(&:size).sort.last
      cloud_parts = []
      cloud_parts << " #{'_' * (max_length + 2)}"
      if text_lines.size == 1
        cloud_parts << "< #{text} >"
      else
        cloud_parts << "/ #{text_lines.first.ljust(max_length, ' ')} \\"
        if text_lines.size > 2
          text_lines[1, text_lines.length - 2].each do |line|
            cloud_parts << "| #{line.ljust(max_length, ' ')} |"
          end
        end
        cloud_parts << "\\ #{text_lines.last.ljust(max_length, ' ')} /"
      end
      cloud_parts << " #{'-' * (max_length + 2)}"
      cloud_parts << <<EOS
       \\   ,__,
        \\  (oo)____
           (__)    )\\
              ||--|| *
EOS
      cloud_parts.join("\n")
    end

  end
end
