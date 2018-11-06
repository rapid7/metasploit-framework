module Pry::Helpers; end
module Pry::Helpers::BaseHelpers
  include Pry::Platform
  extend self

  def silence_warnings
    old_verbose = $VERBOSE
    $VERBOSE = nil
    begin
      yield
    ensure
      $VERBOSE = old_verbose
    end
  end

  # Acts like send but ignores any methods defined below Object or Class in the
  # inheritance hierarchy.
  # This is required to introspect methods on objects like Net::HTTP::Get that
  # have overridden the `method` method.
  def safe_send(obj, method, *args, &block)
    (Module === obj ? Module : Object).instance_method(method).bind(obj).call(*args, &block)
  end
  public :safe_send

  def find_command(name, set = Pry::Commands)
    command_match = set.find do |_, command|
      (listing = command.options[:listing]) == name && listing != nil
    end
    command_match.last if command_match
  end

  def not_a_real_file?(file)
    file =~ /^(\(.*\))$|^<.*>$/ || file =~ /__unknown__/ || file == "" || file == "-e"
  end

  def command_dependencies_met?(options)
    return true if !options[:requires_gem]
    Array(options[:requires_gem]).all? do |g|
      Pry::Rubygem.installed?(g)
    end
  end

  def use_ansi_codes?
    windows_ansi? || ENV['TERM'] && ENV['TERM'] != "dumb"
  end

  def colorize_code(code)
    CodeRay.scan(code, :ruby).term
  end

  def highlight(string, regexp, highlight_color=:bright_yellow)
    string.gsub(regexp) { |match| "<#{highlight_color}>#{match}</#{highlight_color}>" }
  end

  # formatting
  def heading(text)
    text = "#{text}\n--"
    "\e[1m#{text}\e[0m"
  end

  # Send the given text through the best available pager (if Pry.config.pager is
  # enabled). Infers where to send the output if used as a mixin.
  # DEPRECATED.
  def stagger_output(text, out = nil)
    if defined?(_pry_) && _pry_
      _pry_.pager.page text
    else
      Pry.new.pager.page text
    end
  end
end
