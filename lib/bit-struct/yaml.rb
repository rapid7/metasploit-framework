require 'yaml'

class BitStruct
  if RUBY_VERSION == "1.8.2"
    def is_complex_yaml? # :nodoc:
      true
    end

    YAML.add_ruby_type(/^bitstruct/) do |type, val|
      subtype, subclass = YAML.read_type_class(type, Object)
      subclass.new(val)
    end

    def to_yaml_type # :nodoc:
      "!ruby/bitstruct:#{self.class}"
    end

    def to_yaml( opts = {} ) # :nodoc:
      opts[:DocType] = self.class if Hash === opts
      YAML.quick_emit(self.object_id, opts) do |out|
        out.map(to_yaml_type) do |map|
          fields.each do |field|
            fn = field.name
            map.add(fn, send(fn))
          end
        end
      end
    end

  else
    yaml_as "tag:path.berkeley.edu,2006:bitstruct"

    def to_yaml_properties # :nodoc:
      yaml_fields = fields.select {|field| field.inspectable?}
      props = yaml_fields.map {|f| f.name.to_s}
      if (rest_field = self.class.rest_field)
        props << rest_field.name.to_s
      end
      props
    end

    # Return YAML representation of the BitStruct.
    def to_yaml( opts = {} )
      YAML::quick_emit( object_id, opts ) do |out|
        out.map( taguri, to_yaml_style ) do |map|
          to_yaml_properties.each do |m|
            map.add( m, send( m ) )
          end
        end
      end
    end

    def self.yaml_new( klass, tag, val ) # :nodoc:
      unless Hash === val
        raise YAML::TypeError, "Invalid BitStruct: " + val.inspect
      end

      bitstruct_name, bitstruct_type = YAML.read_type_class( tag, BitStruct )

      st = bitstruct_type.new

      val.each do |k,v|
        st.send( "#{k}=", v )
      end

      st
    end
  end
end
