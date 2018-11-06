class Integer
  require 'backports/tools/arguments'

  def anybits?(n)
    n = Backports.coerce_to_int(n)
    n & self != 0
  end
end unless Integer.method_defined? :anybits?
