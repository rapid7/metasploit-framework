require 'bindata/base'
require 'bindata/sanitize'

module BinData
  # An Array is a list of data objects of the same type.
  #
  #   require 'bindata'
  #
  #   data = "\x03\x04\x05\x06\x07\x08\x09"
  #
  #   obj = BinData::Array.new(:type => :int8, :initial_length => 6)
  #   obj.read(data)
  #   obj.snapshot #=> [3, 4, 5, 6, 7, 8]
  #
  #   obj = BinData::Array.new(:type => :int8,
  #                            :read_until => lambda { index == 1 })
  #   obj.read(data)
  #   obj.snapshot #=> [3, 4]
  #
  #   obj = BinData::Array.new(:type => :int8,
  #                            :read_until => lambda { element >= 6 })
  #   obj.read(data)
  #   obj.snapshot #=> [3, 4, 5, 6]
  #
  #   obj = BinData::Array.new(:type => :int8,
  #           :read_until => lambda { array[index] + array[index - 1] == 13 })
  #   obj.read(data)
  #   obj.snapshot #=> [3, 4, 5, 6, 7]
  #		
	#		obj = BinData::Array.new(:type => :int8, :read_until_eof => true)
	#		obj.read(data)
	#		obj.snapshot #=> [3, 4, 5, 6, 7, 8, 9]
	#
	#
  # == Parameters
  #
  # Parameters may be provided at initialisation to control the behaviour of
  # an object.  These params are:
  #
  # <tt>:type</tt>::           The symbol representing the data type of the
  #                            array elements.  If the type is to have params
  #                            passed to it, then it should be provided as
  #                            <tt>[type_symbol, hash_params]</tt>.
  # <tt>:initial_length</tt>:: The initial length of the array.
  # <tt>:read_until</tt>::     While reading, elements are read until this
  #                            condition is true.  This is typically used to
  #                            read an array until a sentinel value is found.
  #                            The variables +index+, +element+ and +array+
  #                            are made available to any lambda assigned to
  #                            this parameter.
  #
  # Each data object in an array has the variable +index+ made available
  # to any lambda evaluated as a parameter of that data object.
  class Array < BinData::Base
    include Enumerable

    # Register this class
    register(self.name, self)

    # These are the parameters used by this class.
    mandatory_parameter :type
    optional_parameters :initial_length, :read_until, :read_until_eof
    mutually_exclusive_parameters :initial_length, :read_until, :read_until_eof

    class << self
      # Returns a sanitized +params+ that is of the form expected
      # by #initialize.
      def sanitize_parameters(sanitizer, params)
        params = params.dup

        unless params.has_key?(:initial_length) or params.has_key?(:read_until) or params.has_key?(:read_until_eof)
          # ensure one of :initial_length, :read_until, or :read_until_eof exists
          params[:initial_length] = 0
        end

        if params.has_key?(:read_length)
          warn ":read_length is not used with arrays.  You probably want to change this to :initial_length"
        end

        if params.has_key?(:type)
          type, el_params = params[:type]
          params[:type] = sanitizer.sanitize(type, el_params)
        end

        super(sanitizer, params)
      end
    end

    # Creates a new Array
    def initialize(params = {}, env = nil)
      super(params, env)

      klass, el_params = param(:type)

      @element_list    = nil
      @element_klass   = klass
      @element_params  = el_params
    end

    # Returns if the element at position +index+ is clear?.  If +index+
    # is not given, then returns whether all fields are clear.
    def clear?(index = nil)
      if @element_list.nil?
        true
      elsif index.nil?
        elements.each { |f| return false if not f.clear? }
        true
      else
        (index < elements.length) ? elements[index].clear? : true
      end
    end

    # Clears the element at position +index+.  If +index+ is not given, then
    # the internal state of the array is reset to that of a newly created
    # object.
    def clear(index = nil)
      if @element_list.nil?
        # do nothing as the array is already clear
      elsif index.nil?
        @element_list = nil
      elsif index < elements.length
        elements[index].clear
      end
    end

    # Returns whether this data object contains a single value.  Single
    # value data objects respond to <tt>#value</tt> and <tt>#value=</tt>.
    def single_value?
      return false
    end

    # To be called after calling #do_read.
    def done_read
      elements.each { |f| f.done_read }
    end

    # Appends a new element to the end of the array.  If the array contains
    # single_values then the +value+ may be provided to the call.
    # Returns the appended object, or value in the case of single_values.
    def append(value = nil)
      # TODO: deprecate #append as it can be replaced with #push
      append_new_element
      self[-1] = value unless value.nil?
      self.last
    end

    # Pushes the given object(s) on to the end of this array. 
    # This expression returns the array itself, so several appends may 
    # be chained together.
    def push(*args)
      args.each do |arg|
        if @element_klass == arg.class
          # TODO: need to modify arg.env to add_variable(:index) and
          # to link arg.env to self.env
          elements.push(arg)
        else
          append(arg)
        end
      end
      self
    end

    # Returns the element at +index+.  If the element is a single_value
    # then the value of the element is returned instead.
    def [](*args)
      if args.length == 1 and ::Integer === args[0]
        # extend array automatically
        while args[0] >= elements.length
          append_new_element
        end
      end

      data = elements[*args]
      if data.respond_to?(:each)
        data.collect { |el| (el && el.single_value?) ? el.value : el }
      else
        (data && data.single_value?) ? data.value : data
      end
    end
    alias_method :slice, :[]

    # Sets the element at +index+.  If the element is a single_value
    # then the value of the element is set instead.
    def []=(index, value)
      # extend array automatically
      while index >= elements.length
        append_new_element
      end

      obj = elements[index]
      unless obj.single_value?
        # TODO: allow setting objects, not just values
        raise NoMethodError, "undefined method `[]=' for #{self}", caller
      end
      obj.value = value
    end

    # Iterate over each element in the array.  If the elements are
    # single_values then the values of the elements are iterated instead.
    def each
      elements.each do |el|
        yield(el.single_value? ? el.value : el)
      end
    end

    # Returns the first element, or the first +n+ elements, of the array.
    # If the array is empty, the first form returns nil, and the second
    # form returns an empty array.
    def first(n = nil)
      if n.nil?
        if elements.empty?
          # explicitly return nil as arrays grow automatically
          nil
        else
          self[0]
        end
      else
        self[0, n]
      end
    end

    # Returns the last element, or the last +n+ elements, of the array.
    # If the array is empty, the first form returns nil, and the second
    # form returns an empty array.
    def last(n = nil)
      if n.nil?
        self[-1]
      else
        n = length if n > length
        self[-n, n]
      end
    end

    # The number of elements in this array.
    def length
      elements.length
    end
    alias_method :size, :length

    # Returns true if self array contains no elements.
    def empty?
      length.zero?
    end

    # Allow this object to be used in array context.
    def to_ary
      snapshot
    end

    #---------------
    private

    # Reads the values for all fields in this object from +io+.
    def _do_read(io)
      if has_param?(:initial_length)
        elements.each { |f| f.do_read(io) }
			elsif has_param?(:read_until)
        @element_list = nil
        loop do
          element = append_new_element
          element.do_read(io)
          variables = { :index => self.length - 1, :element => self.last,
                        :array => self }
          finished = eval_param(:read_until, variables)
          break if finished
        end
			else # :read_until_eof
				loop do
						element = append_new_element
					begin
						element.do_read(io)
					rescue EOFError
						finished = true
						remove_last_element
					end
					variables = { :index => self.length - 1, :element => self.last,
												:array => self }
					break if finished
        end
			end
    end

    # Writes the values for all fields in this object to +io+.
    def _do_write(io)
      elements.each { |f| f.do_write(io) }
    end

    # Returns the number of bytes it will take to write the element at
    # +index+.  If +index+, then returns the number of bytes required
    # to write all fields.
    def _do_num_bytes(index)
      if index.nil?
        (elements.inject(0) { |sum, f| sum + f.do_num_bytes }).ceil
      else
        elements[index].do_num_bytes
      end
    end

    # Returns a snapshot of the data in this array.
    def _snapshot
      elements.collect { |e| e.snapshot }
    end

    # Returns the list of all elements in the array.  The elements
    # will be instantiated on the first call to this method.
    def elements
      if @element_list.nil?
        @element_list = []
        if has_param?(:initial_length)
          # create the desired number of instances
          eval_param(:initial_length).times do
            append_new_element
          end
        end
      end
      @element_list
    end

    # Creates a new element and appends it to the end of @element_list.
    # Returns the newly created element
    def append_new_element
      # ensure @element_list is initialised
      elements()

      env = create_env
      env.add_variable(:index, @element_list.length)
      element = @element_klass.new(@element_params, env)
      @element_list << element
      element
    end

		# Pops the last element off the end of @element_list.
		# Returns the popped element.
		# This is important for the :read_until_eof option to properly close
		# the do_read io handle.
		def remove_last_element
			elements()
			@element_list.pop
		end
  end
end