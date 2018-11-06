require 'time'
require 'date'

module SQLite3

  # The Translator class encapsulates the logic and callbacks necessary for
  # converting string data to a value of some specified type. Every Database
  # instance may have a Translator instance, in order to assist in type
  # translation (Database#type_translation).
  #
  # Further, applications may define their own custom type translation logic
  # by registering translator blocks with the corresponding database's
  # translator instance (Database#translator).
  class Translator

    # Create a new Translator instance. It will be preinitialized with default
    # translators for most SQL data types.
    def initialize
      @translators = Hash.new( proc { |type,value| value } )
      @type_name_cache = {}
      register_default_translators
    end

    # Add a new translator block, which will be invoked to process type
    # translations to the given type. The type should be an SQL datatype, and
    # may include parentheses (i.e., "VARCHAR(30)"). However, any parenthetical
    # information is stripped off and discarded, so type translation decisions
    # are made solely on the "base" type name.
    #
    # The translator block itself should accept two parameters, "type" and
    # "value". In this case, the "type" is the full type name (including
    # parentheses), so the block itself may include logic for changing how a
    # type is translated based on the additional data. The "value" parameter
    # is the (string) data to convert.
    #
    # The block should return the translated value.
    def add_translator( type, &block ) # :yields: type, value
      warn(<<-eowarn) if $VERBOSE
#{caller[0]} is calling `add_translator`.
Built in translators are deprecated and will be removed in version 2.0.0
      eowarn
      @translators[ type_name( type ) ] = block
    end

    # Translate the given string value to a value of the given type. In the
    # absense of an installed translator block for the given type, the value
    # itself is always returned. Further, +nil+ values are never translated,
    # and are always passed straight through regardless of the type parameter.
    def translate( type, value )
      unless value.nil?
        # FIXME: this is a hack to support Sequel
        if type && %w{ datetime timestamp }.include?(type.downcase)
          @translators[ type_name( type ) ].call( type, value.to_s )
        else
          @translators[ type_name( type ) ].call( type, value )
        end
      end
    end

    # A convenience method for working with type names. This returns the "base"
    # type name, without any parenthetical data.
    def type_name( type )
      @type_name_cache[type] ||= begin
        type = "" if type.nil?
        type = $1 if type =~ /^(.*?)\(/
        type.upcase
      end
    end
    private :type_name

    # Register the default translators for the current Translator instance.
    # This includes translators for most major SQL data types.
    def register_default_translators
      [ "time",
        "timestamp" ].each { |type| add_translator( type ) { |t, v| Time.parse( v ) } }

      add_translator( "date" ) { |t,v| Date.parse(v) }
      add_translator( "datetime" ) { |t,v| DateTime.parse(v) }

      [ "decimal",
        "float",
        "numeric",
        "double",
        "real",
        "dec",
        "fixed" ].each { |type| add_translator( type ) { |t,v| v.to_f } }

      [ "integer",
        "smallint",
        "mediumint",
        "int",
        "bigint" ].each { |type| add_translator( type ) { |t,v| v.to_i } }

      [ "bit",
        "bool",
        "boolean" ].each do |type|
        add_translator( type ) do |t,v|
          !( v.strip.gsub(/00+/,"0") == "0" ||
             v.downcase == "false" ||
             v.downcase == "f" ||
             v.downcase == "no" ||
             v.downcase == "n" )
        end
      end

      add_translator( "tinyint" ) do |type, value|
        if type =~ /\(\s*1\s*\)/
          value.to_i == 1
        else
          value.to_i
        end
      end
    end
    private :register_default_translators

  end

end
