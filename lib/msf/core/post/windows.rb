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

  # Escape a string literal value to be included as an argument to powershell.exe.
  # This will help in cases where one might need to use & as in PowerShell this is
  # a reserved character whereas in cmd.exe this is used to indicate the start
  # of an additional command to execute.
  #
  # Example (without this escaping):
  # powershell -Command "cmd /c echo hello & echo world" <- This will result in errors as & is a reserved character.
  # powershell -Command "cmd.exe /c 'echo hello & echo world'" <- This will succeed as & is interpreted as part of a string by PowerShell.
  #
  # In our case we use PowerShell quoting as described at https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules?view=powershell-7.3
  # which states that to use a single quote inside of a single quoted string, use a second consecutive single quote.
  # Therefore this is valid in PowerShell: 'don''t'
  # Which in turn becomes the string "don't" (sans double quotes) inside PowerShell.
  #
  # @param string [String] The string to escape for use with powershell.exe.
  # @return [String] The escaped string.
  def self.escape_powershell_literal(string)
    string = string.dup
    string.gsub!("'", "''")
    string
  end
end
