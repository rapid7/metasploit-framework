unless Regexp.respond_to? :try_convert
  require 'backports/tools/arguments'

  def Regexp.try_convert(obj)
    Backports.try_convert(obj, Regexp, :to_regexp)
  end
end
