class Integer
  require 'backports/tools/arguments'

  def allbits?(n)
    n = Backports.coerce_to_int(n)
    n & self == n
  end
end unless Integer.method_defined? :allbits?
