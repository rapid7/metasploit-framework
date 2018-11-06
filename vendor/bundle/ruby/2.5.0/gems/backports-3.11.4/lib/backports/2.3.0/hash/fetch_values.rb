unless Hash.method_defined? :fetch_values
  class Hash
    def fetch_values(*keys, &block)
      keys.map do |k|
        fetch(k, &block)
      end
    end
  end
end
