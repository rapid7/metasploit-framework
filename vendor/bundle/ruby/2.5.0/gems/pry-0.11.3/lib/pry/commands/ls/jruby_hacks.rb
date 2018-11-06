module Pry::Command::Ls::JRubyHacks

  private

  # JRuby creates lots of aliases for methods imported from java in an attempt
  # to make life easier for ruby programmers.  (e.g. getFooBar becomes
  # get_foo_bar and foo_bar, and maybe foo_bar? if it returns a Boolean). The
  # full transformations are in the assignAliases method of:
  # https://github.com/jruby/jruby/blob/master/src/org/jruby/javasupport/JavaClass.java
  #
  # This has the unfortunate side-effect of making the output of ls even more
  # incredibly verbose than it normally would be for these objects; and so we
  # filter out all but the nicest of these aliases here.
  #
  # TODO: This is a little bit vague, better heuristics could be used.
  #       JRuby also has a lot of scala-specific logic, which we don't copy.
  def trim_jruby_aliases(methods)
    grouped = methods.group_by do |m|
      m.name.sub(/\A(is|get|set)(?=[A-Z_])/, '').gsub(/[_?=]/, '').downcase
    end

    grouped.flat_map do |key, values|
      values = values.sort_by do |m|
        rubbishness(m.name)
      end

      found = []
      values.select do |x|
        (!found.any? { |y| x == y }) && found << x
      end
    end
  end

  # When removing jruby aliases, we want to keep the alias that is
  # "least rubbish" according to this metric.
  def rubbishness(name)
    name.each_char.map { |x|
      case x
      when /[A-Z]/
        1
      when '?', '=', '!'
        -2
      else
        0
      end
    }.inject(&:+) + (name.size / 100.0)
  end

end
