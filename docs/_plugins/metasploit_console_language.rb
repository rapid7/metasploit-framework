require 'rouge'

# Custom highlighting support for Metasploit's prompt
# https://rouge-ruby.github.io/docs/file.LexerDevelopment.html
module Rouge
  # Custom tokens specific to Msf, as the inbuilt lexer tokens can't capture
  # the detail required for Msf's print_warning/print_good/etc calls.
  module Tokens
    def self.token(name, shortname, &b)
      tok = Token.make_token(name, shortname, &b)
      const_set(name, tok)
    end

    # The 'shortname' is the class used when generating the HTML. It is intentionally
    # short to reduce HTML size.
    # https://github.com/rouge-ruby/rouge/blob/a4ed658d2778a3e2d3e68873f7221b91149a2ed4/lib/rouge/token.rb#L69
    SHORTNAME = 'z'

    token :Msf, SHORTNAME do
      # prompt - msf / msf5 / msf6 / meterpreter
      token :Prompt, "#{SHORTNAME}p"
      # [-]
      token :Error, "#{SHORTNAME}e"
      # [+]
      token :Good, "#{SHORTNAME}g"
      # [*]
      token :Status, "#{SHORTNAME}s"
      # [!]
      token :Warning, "#{SHORTNAME}w"
    end
  end

  module Lexers
    class MetasploitConsoleLanguage < Rouge::RegexLexer
      title 'msf'
      tag 'msf'
      desc 'Metasploit console highlighter'
      filenames []
      mimetypes []

      def self.keywords
        @keywords ||= Set.new %w()
      end

      state :whitespace do
        rule %r/\s+/, Text
      end

      state :root do
        mixin :whitespace

        # Match msf, msf5, msf6, meterpreter
        rule %r{^(msf\d?|meterpreter)}, Tokens::Msf::Prompt, :msf_prompt
        rule %r{^\[-\]}, Tokens::Msf::Error
        rule %r{^\[\+\]}, Tokens::Msf::Good
        rule %r{^\[\*\]}, Tokens::Msf::Status
        rule %r{^\[\!\]}, Tokens::Msf::Warning
        rule %r{.+}, Text
      end

      # State for highlighting the prompt such as
      # msf6 auxiliary(admin/dcerpc/cve_2022_26923_certifried) >
      state :msf_prompt do
        mixin :whitespace

        rule %r{exploit|payload|auxiliary|encoder|evasion|post|nop}, Text
        rule %r{\(}, Punctuation
        rule %r{\)}, Punctuation
        rule %r{[\w/]+}, Keyword::Constant
        rule %r{>}, Punctuation, :pop!
      end
    end
  end
end
