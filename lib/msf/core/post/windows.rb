# -*- coding: binary -*-

module Msf::Post::Windows
  # Escape a string literal value to be included as an argument to cmd.exe. The escaped value *should not* be placed
  # within double quotes as this will alter now it is evaluated (e.g. `echo "^"((^&test) Foo^""` is different than
  # `echo ^"((^&test) Foo^"`.
  #
  # @param [String] string The string to escape for use with cmd.exe.
  # @param [Boolean] spaces Whether or not to escape spaces. If the string is being passed to echo, set this to false
  #   otherwise if it's an argument, set it to true.
  # @return [String] The escaped string.
  def self.escape_cmd_literal(string, spaces:)
    string = string.dup
    %w[ ^ & < > | " ].each { |char| string.gsub!(char, "^#{char}") }
    string.gsub!(' ', '" "') if spaces
    string
  end
end
