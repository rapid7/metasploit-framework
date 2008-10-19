require 'bindata/base'
require 'bindata/sanitize'

module BinData
  # A Struct is an ordered collection of named data objects.
  #
  #    require 'bindata'
  #
  #    class Tuple < BinData::MultiValue
  #      int8  :x
  #      int8  :y
  #      int8  :z
  #    end
  #
  #    obj = BinData::Struct.new(:hide => :a,
  #                              :fields => [ [:int32le, :a],
  #                                           [:int16le, :b],
  #                                           [:tuple, :s] ])
  #    obj.field_names   =># ["b", "s"]
  #
  #
  # == Parameters
  #
  # Parameters may be provided at initialisation to control the behaviour of
  # an object.  These params are:
  #
  # <tt>:fields</tt>::   An array specifying the fields for this struct.
  #                      Each element of the array is of the form [type, name,
  #                      params].  Type is a symbol representing a registered
  #                      type.  Name is the name of this field.  Params is an
  #                      optional hash of parameters to pass to this field
  #                      when instantiating it.
  # <tt>:hide</tt>::     A list of the names of fields that are to be hidden
  #                      from the outside world.  Hidden fields don't appear
  #                      in #snapshot or #field_names but are still accessible
  #                      by name.
  # <tt>:endian</tt>::   Either :little or :big.  This specifies the default
  #                      endian of any numerics in this struct, or in any
  #                      nested data objects.
  class Struct < BinData::Base

    # These reserved words may not be used as field names
    RESERVED = (::Hash.instance_methods + 
                %w{alias and begin break case class def defined do else elsif
                   end ensure false for if in module next nil not or redo
                   rescue retry return self super then true undef unless until
                   when while yield }).uniq

    # Register this class
    register(self.name, self)

    # A hash that can be accessed via attributes.
    class Snapshot < Hash #:nodoc:
      def method_missing(symbol, *args)
        self[symbol.id2name] || super
      end
    end

    class << self
      #### DEPRECATION HACK to allow inheriting from BinData::Struct
      #
      def inherited(subclass) #:nodoc:
        if subclass != MultiValue
          # warn about deprecated method - remove before releasing 1.0
          warn "warning: inheriting from BinData::Struct in deprecated. Inherit from BinData::MultiValue instead."

          register(subclass.name, subclass)
        end
      end
      def endian(endian = nil)
        @endian ||= nil
        if [:little, :big].include?(endian)
          @endian = endian
        elsif endian != nil
          raise ArgumentError, "unknown value for endian '#{endian}'"
        end
        @endian
      end
      def hide(*args)
        # note that fields are stored in an instance variable not a class var
        @hide ||= []
        args.each do |name|
          @hide << name.to_s
        end
        @hide
      end
      def fields
        @fields || []
      end
      def method_missing(symbol, *args)
        name, params = args

        type = symbol
        name = name.to_s
        params ||= {}

        # note that fields are stored in an instance variable not a class var
        @fields ||= []

        # check that type is known
        unless Sanitizer.type_exists?(type, endian)
          raise TypeError, "unknown type '#{type}' for #{self}", caller
        end

        # check for duplicate names
        @fields.each do |t, n, p|
          if n == name
            raise SyntaxError, "duplicate field '#{name}' in #{self}", caller
          end
        end

        # check that name doesn't shadow an existing method
        if self.instance_methods.include?(name)
          raise NameError.new("", name),
                "field '#{name}' shadows an existing method", caller
        end

        # check that name isn't reserved
        if self::RESERVED.include?(name)
          raise NameError.new("", name),
                "field '#{name}' is a reserved name", caller
        end

        # remember this field.  These fields will be recalled upon creating
        # an instance of this class
        @fields.push([type, name, params])
      end
      def deprecated_hack!(params)
        # possibly override endian
        endian = params[:endian] || self.endian
        params[:endian] = endian unless endian.nil?
        params[:fields] = params[:fields] || self.fields
        params[:hide] = params[:hide] || self.hide
      end
      #
      #### DEPRECATION HACK to allow inheriting from BinData::Struct


      # Ensures that +params+ is of the form expected by #initialize.
      def sanitize_parameters!(sanitizer, params)
        #### DEPRECATION HACK to allow inheriting from BinData::Struct
        #
        deprecated_hack!(params)
        #
        #### DEPRECATION HACK to allow inheriting from BinData::Struct

        # possibly override endian
        endian = params[:endian]
        if endian != nil
          unless [:little, :big].include?(endian)
            raise ArgumentError, "unknown value for endian '#{endian}'"
          end

          params[:endian] = endian
        end

        if params.has_key?(:fields)
          sanitizer.with_endian(endian) do
            # ensure names of fields are strings and that params is sanitized
            all_fields = params[:fields].collect do |ftype, fname, fparams|
              fname = fname.to_s
              klass, sanitized_fparams = sanitizer.sanitize(ftype, fparams)
              [klass, fname, sanitized_fparams]
            end
            params[:fields] = all_fields
          end

          # now params are sanitized, check that parameter names are okay
          field_names = []
          instance_methods = self.instance_methods
          reserved_names = RESERVED

          params[:fields].each do |fklass, fname, fparams|

            # check that name doesn't shadow an existing method
            if instance_methods.include?(fname)
              raise NameError.new("Rename field '#{fname}' in #{self}, " +
                                  "as it shadows an existing method.", fname)
            end

            # check that name isn't reserved
            if reserved_names.include?(fname)
              raise NameError.new("Rename field '#{fname}' in #{self}, " +
                                  "as it is a reserved name.", fname)
            end

            # check for multiple definitions
            if field_names.include?(fname)
              raise NameError.new("field '#{fname}' in #{self}, " +
                                  "is defined multiple times.", fname)
            end

            field_names << fname
          end

          # collect all hidden names that correspond to a field name
          hide = []
          if params.has_key?(:hide)
            hidden = (params[:hide] || []).collect { |h| h.to_s }
            all_field_names = params[:fields].collect { |k,n,p| n }
            hide = hidden & all_field_names
          end
          params[:hide] = hide
        end

        super(sanitizer, params)
      end
    end

    # These are the parameters used by this class.
    mandatory_parameter :fields
    optional_parameters :endian, :hide

    # Creates a new Struct.
    def initialize(params = {}, env = nil)
      super(params, env)

      # extract field names but don't instantiate the fields
      @field_names = param(:fields).collect { |k, n, p| n }
      @field_objs  = []
    end

    # Clears the field represented by +name+.  If no +name+
    # is given, clears all fields in the struct.
    def clear(name = nil)
      if name.nil?
        @field_objs.each { |f| f.clear unless f.nil? }
      else
        obj = find_obj_for_name(name.to_s)
        obj.clear unless obj.nil?
      end
    end

    # Returns if the field represented by +name+ is clear?.  If no +name+
    # is given, returns whether all fields are clear.
    def clear?(name = nil)
      if name.nil?
        @field_objs.each do |f|
          return false unless f.nil? or f.clear?
        end
        true
      else
        obj = find_obj_for_name(name.to_s)
        obj.nil? ? true : obj.clear?
      end
    end

    # Returns whether this data object contains a single value.  Single
    # value data objects respond to <tt>#value</tt> and <tt>#value=</tt>.
    def single_value?
      return false
    end

    # Returns a list of the names of all fields accessible through this
    # object.  +include_hidden+ specifies whether to include hidden names
    # in the listing.
    def field_names(include_hidden = false)
      # collect field names
      names = []
      hidden = param(:hide)
      @field_names.each do |name|
        if include_hidden or not hidden.include?(name)
          names << name
        end
      end
      names
    end

    # To be called after calling #read.
    def done_read
      @field_objs.each { |f| f.done_read unless f.nil? }
    end

    # Returns the data object that stores values for +name+.
    def find_obj_for_name(name)
      idx = @field_names.index(name)
      if idx
        instantiate_obj(idx)
        @field_objs[idx]
      else
        nil
      end
    end

    def offset_of(field)
      idx = @field_names.index(field.to_s)
      if idx
        instantiate_all

        offset = 0
        (0...idx).each do |i|
          this_offset = @field_objs[i].do_num_bytes
          if ::Float === offset and ::Integer === this_offset
            offset = offset.ceil
          end
          offset += this_offset
        end
        offset
      else
        nil
      end
    end

    # Override to include field names
    alias_method :orig_respond_to?, :respond_to?
    def respond_to?(symbol, include_private = false)
      orig_respond_to?(symbol, include_private) ||
        field_names(true).include?(symbol.id2name.chomp("="))
    end

    def method_missing(symbol, *args, &block)
      name = symbol.id2name

      is_writer = (name[-1, 1] == "=")
      name.chomp!("=")

      # find the object that is responsible for name
      if (obj = find_obj_for_name(name))
        # pass on the request
        if obj.single_value? and is_writer
          obj.value = *args
        elsif obj.single_value?
          obj.value
        else
          obj
        end
      else
        super
      end
    end

    #---------------
    private

    # Instantiates all fields.
    def instantiate_all
      (0...@field_names.length).each { |idx| instantiate_obj(idx) }
    end

    # Instantiates the field object at position +idx+.
    def instantiate_obj(idx)
      if @field_objs[idx].nil?
        fklass, fname, fparams = param(:fields)[idx]
        @field_objs[idx] = fklass.new(fparams, create_env)
      end
    end

    # Reads the values for all fields in this object from +io+.
    def _do_read(io)
      instantiate_all
      @field_objs.each { |f| f.do_read(io) }
    end

    # Writes the values for all fields in this object to +io+.
    def _do_write(io)
      instantiate_all
      @field_objs.each { |f| f.do_write(io) }
    end

    # Returns the number of bytes it will take to write the field represented
    # by +name+.  If +name+ is nil then returns the number of bytes required
    # to write all fields.
    def _do_num_bytes(name)
      if name.nil?
        instantiate_all
        (@field_objs.inject(0) { |sum, f| sum + f.do_num_bytes }).ceil
      else
        obj = find_obj_for_name(name.to_s)
        obj.nil? ? 0 : obj.do_num_bytes
      end
    end

    # Returns a snapshot of this struct as a hash.
    def _snapshot
      hash = Snapshot.new
      field_names.each do |name|
        ss = find_obj_for_name(name).snapshot
        hash[name] = ss unless ss.nil?
      end
      hash
    end
  end
end