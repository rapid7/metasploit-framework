module XDR::DSL::Struct
  def attribute(name, type)

    unless type.is_a?(XDR::Concerns::ConvertsToXDR)
      raise ArgumentError, "#{type} does not convert to xdr"
    end

    self.fields = self.fields.merge(name => type)

    define_method name do
      read_attribute(name)
    end

    define_method "#{name}=" do |v|
      write_attribute(name, v)
    end

    define_attribute_methods name
  end
end
