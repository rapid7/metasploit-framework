require 'xdr'

class Signature < XDR::Struct
  attribute :public_key, XDR::Opaque[32]
  attribute :data, XDR::Opaque[32]
end

class Envelope < XDR::Struct
  attribute :body,      XDR::VarOpaque[]
  attribute :timestamp, XDR::Int
  attribute :signature, Signature
end

sig            = Signature.new()
sig.public_key = "\x01" * 32
sig.data       = "\x00" * 32

env = Envelope.new({
  signature: sig,
  body: "hello",
  timestamp: Time.now.to_i
})

env.to_xdr
