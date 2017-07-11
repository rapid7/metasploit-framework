# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

class LibraryWrapper
  attr_reader :_client, :_library

  def initialize(library, client)
    @_library    = library
    @_client = client
  end

  # For backwards compatability. People check if functions are added this way
  # XXX: Depricate this
  def functions
    # warn 'Depricated.'
    _library.functions
  end

  def method_missing(sym, *args)
    _library.call_function(sym, args, _client)
  end
end

end; end; end; end; end; end
