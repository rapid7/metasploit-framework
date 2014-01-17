# Current Design

Metasploit payload modules are Ruby `Modules` and come in three types:
 * `Payload::Type::Single`
 * `Payload::Type::Stage`
 * `Payload::Type::Stager`

Payloads are created by creating an anonymous `Class` and including
mixins for a `Handler` and either a single-stage payload or both a stage
and stager, like so:

```ruby
def build_payload(*modules)
  klass = Class.new(Payload)

  # Remove nil modules
  modules.compact!

  # Include the modules supplied to us with the mad skillz
  # spoonfu style
  klass.include(*modules.reverse)

  return klass
end
```

The result is a `Class` for each combination of stage + stager +
handler.  E.g., `windows/meterpreter/reverse_tcp` includes
`Msf::Handler::ReverseTcp` and the `Modules` defined in
`modules/payloads/stagers/windows/reverse_tcp` and
`modules/payloads/stages/windows/meterpreter`. As a corollary, this
means that stages and stagers are intricately linked with each other and
their handlers.


