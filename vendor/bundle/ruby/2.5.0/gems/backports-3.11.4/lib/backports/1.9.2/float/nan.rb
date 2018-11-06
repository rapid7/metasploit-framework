unless Float.const_defined? :NAN
  Float::NAN = 0.0/0.0
end
