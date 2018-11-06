unless Float.method_defined? :fdiv
  Float.send :alias_method, :fdiv, :/
end
