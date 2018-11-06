class Array
  alias_method :prepend, :unshift unless [].respond_to?(:prepend)
end
