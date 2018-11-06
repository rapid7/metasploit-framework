class File
  module Constants
    # In Ruby 1.8, it is defined only on Windows
    BINARY = 0 unless const_defined?(:BINARY)
  end
end
