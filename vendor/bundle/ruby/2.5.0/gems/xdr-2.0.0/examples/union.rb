require 'xdr'

class ResultType < XDR::Enum
  member :ok,       0
  member :error,    1
  member :nonsense, 2
  seal
end

class Result < XDR::Union
  switch_on ResultType, :type

  switch :ok
  switch :error, :message
  switch :default

  attribute :message, XDR::String[]
end

r = Result.new()
r.set(:error, "hello")
r.message! # => "hello"
r.get # => "hello"

r.set(:ok)
r.get # => nil

r.set(:nonsense)
r.get # => nil
