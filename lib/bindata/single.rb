require 'bindata/base'

module BinData
  # A BinData::Single object is a container for a value that has a particular
  # binary representation.  A value corresponds to a primitive type such as
  # as integer, float or string.  Only one value can be contained by this
  # object.  This value can be read from or written to an IO stream.
  #
  #   require 'bindata'
  #
  #   obj = BinData::Uint8.new(:initial_value => 42)
  #   obj.value #=> 42
  #   obj.value = 5
  #   obj.value #=> 5
  #   obj.clear
  #   obj.value #=> 42
  #
  #   obj = BinData::Uint8.new(:value => 42)
  #   obj.value #=> 42
  #   obj.value = 5
  #   obj.value #=> 42
  #
  #   obj = BinData::Uint8.new(:check_value => 3)
  #   obj.read("\005") #=> BinData::ValidityError: value is '5' but expected '3'
  #
  #   obj = BinData::Uint8.new(:check_value => lambda { value < 5 })
  #   obj.read("\007") #=> BinData::ValidityError: value not as expected
  #
  # == Parameters
  #
  # Parameters may be provided at initialisation to control the behaviour of
  # an object.  These params include those for BinData::Base as well as:
  #
  # [<tt>:initial_value</tt>] This is the initial value to use before one is
  #                           either #read or explicitly set with #value=.
  # [<tt>:value</tt>]         The object will always have this value.
  #                           Explicitly calling #value= is prohibited when
  #                           using this param.  In the interval between
  #                           calls to #do_read and #done_read, #value
  #                           will return the value of the data read from the
  #                           IO, not the result of the <tt>:value</tt> param.
  # [<tt>:check_value</tt>]   Raise an error unless the value read in meets
  #                           this criteria.  The variable +value+ is made
  #                           available to any lambda assigned to this
  #                           parameter.  A boolean return indicates success
  #                           or failure.  Any other return is compared to
  #                           the value just read in.
  class Single < BinData::Base
    # These are the parameters used by this class.
    optional_parameters :initial_value, :value, :check_value
    mutually_exclusive_parameters :initial_value, :value

    def initialize(params = {}, env = nil)
      super(params, env)
      clear
    end

    # Resets the internal state to that of a newly created object.
    def clear
      @value = nil
      @in_read = false
    end

    # Returns if the value of this data has been read or explicitly set.
    def clear?
      @value.nil?
    end

    # Single objects are single_values
    def single_value?
      true
    end

    # To be called after calling #do_read.
    def done_read
      @in_read = false
    end

    # Returns the current value of this data.
    def value
      _value
    end

    # Sets the value of this data.
    def value=(v)
      # only allow modification if the value isn't predefined
      unless has_param?(:value)
        raise ArgumentError, "can't set a nil value" if v.nil?
        @value = v

        # Note that this doesn't do anything in ruby 1.8.x so ignore for now
        # # explicitly return the output of #value as v may be different
        # self.value
      end
    end

    #---------------
    private

    # Reads the value for this data from +io+.
    def _do_read(io)
      @in_read = true
      @value   = read_val(io)

      # does the value meet expectations?
      if has_param?(:check_value)
        current_value = self.value
        expected = eval_param(:check_value, :value => current_value)
        if not expected
          raise ValidityError, "value '#{current_value}' not as expected"
        elsif current_value != expected and expected != true
          raise ValidityError, "value is '#{current_value}' but " +
                               "expected '#{expected}'"
        end
      end
    end

    # Writes the value for this data to +io+.
    def _do_write(io)
      raise "can't write whilst reading" if @in_read
      io.writebytes(val_to_str(_value))
    end

    # Returns the number of bytes it will take to write this data.
    def _do_num_bytes(ignored)
      val_to_str(_value).length
    end

    # Returns a snapshot of this data object.
    def _snapshot
      value
    end

    # The unmodified value of this data object.  Note that #value calls this
    # method.  This is so that #value can be overridden in subclasses to 
    # modify the value.
    def _value
      # Table of possible preconditions and expected outcome
      #   1. :value and !in_read          ->   :value
      #   2. :value and in_read           ->   @value
      #   3. :initial_value and clear?    ->   :initial_value
      #   4. :initial_value and !clear?   ->   @value
      #   5. clear?                       ->   sensible_default
      #   6. !clear?                      ->   @value

      if not @in_read and (evaluated_value = eval_param(:value))
        # rule 1 above
        evaluated_value
      else
        # combining all other rules gives this simplified expression
        @value || eval_param(:value) ||
          eval_param(:initial_value) || sensible_default()
      end
    end

    ###########################################################################
    # To be implemented by subclasses

    # Return the string representation that +val+ will take when written.
    def val_to_str(val)
      raise NotImplementedError
    end

    # Read a number of bytes from +io+ and return the value they represent.
    def read_val(io)
      raise NotImplementedError
    end

    # Return a sensible default for this data.
    def sensible_default
      raise NotImplementedError
    end

    # To be implemented by subclasses
    ###########################################################################
  end
end