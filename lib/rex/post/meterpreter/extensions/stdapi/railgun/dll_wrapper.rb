# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class DLLWrapper
  attr_reader :_client, :_dll

  def initialize(dll, client)
    @_dll    = dll
    @_client = client
  end

  # For backwards compatability. People check if functions are added this way
  # XXX: Depricate this
  def functions
    # warn 'Depricated.'
    _dll.functions
  end

  def method_missing(sym, *args)
    _dll.call_function(sym, args, _client)
  end
end
end; end; end; end; end; end
