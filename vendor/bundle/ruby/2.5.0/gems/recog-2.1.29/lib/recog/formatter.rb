module Recog
class Formatter
  COLORS = {
    :red    => 31,
    :yellow => 33,
    :green  => 32,
    :white  => 15
  }

  attr_reader :options, :output

  def initialize(options, output)
    @options = options
    @output  = output || StringIO.new
  end

  def status_message(text)
    output.puts color(text, :white)
  end

  def success_message(text)
    output.puts color(text, :green)
  end

  def warning_message(text)
    output.puts color(text, :yellow)
  end

  def failure_message(text)
    output.puts color(text, :red)
  end

  private

  def color_enabled?
    options.color
  end

  def color(text, color_code)
    color_enabled? ? colorize(text, color_code) : text
  end

  def colorize(text, color_code)
    "\e[#{color_code_for(color_code)}m#{text}\e[0m"
  end

  def color_code_for(code)
    COLORS.fetch(code) { COLORS.fetch(:white) }
  end
end
end
