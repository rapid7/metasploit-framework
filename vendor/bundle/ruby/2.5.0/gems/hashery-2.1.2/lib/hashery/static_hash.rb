module Hashery

  # StaticHash ia a Hash object which raises an error if any
  # previously-defined key attempts to be set again.
  #
  #     foo = StaticHash.new
  #     foo['name'] = 'Tom'    #=> 'Tom'
  #     foo['age']  = 30       #=> 30
  #     foo['name'] = 'Bob'
  #
  # produces
  #
  #     ArgumentError: Duplicate key for StaticHash -- 'name'
  #
  # StaticHash has it's orgins in Gavin Kistner's WriteOnceHash
  # class found in his +basiclibrary.rb+ script.
  #
  # TODO: Maybe StaticHash isn't bets name for this class?
  #
  class StaticHash < CRUDHash

    #
    # Set a value for a key. Raises an error if that key already
    # exists with a different value.
    #
    # key   - Index key to associate with value.
    # value - Value to associate with key.
    #
    # Retruns value.
    #
    def store(key, value)
      if key?(key) && fetch(key) != value
        raise ArgumentError, "Duplicate key for StaticHash -- #{key.inspect}"
      end
      super(key, value)
    end

    #
    #def update(hash)
    #  dups = (keys | hash.keys)
    #  if dups.empty?
    #    super(hash)
    #  else
    #    raise ArgumentError, "Duplicate key for StaticHash -- #{dups.inspect}"
    #  end
    #end

    #
    #alias_method :merge!, :update

  end

end
