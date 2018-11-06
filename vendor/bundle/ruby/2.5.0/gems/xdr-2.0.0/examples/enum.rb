require 'xdr'

class Color < XDR::Enum
  member :red, 0
  member :green, 1
  member :blue, 2

  seal
end

class ResultType < XDR::Enum
  member :ok, 0
  member :error, 1
  seal
end

Color.members           # => {:red => 0, :green => 1, :blue => 2}
Color.members.keys      # => [:red, :green, :blue]

# string and symbol work
# any casing that can be underscored to the correct value will work
Color.from_name(:RED)   # => #<Color:... @name="red", @value=0>
Color.from_name("RED")  # => #<Color:... @name="red", @value=0>
Color.from_name("red")  # => #<Color:... @name="red", @value=0>
Color.from_name(:red)  # => #<Color:... @name="red", @value=0>

Color.from_xdr("\x00\x00\x00\x00") # => #<Color:... @name="red", @value=0>
Color.to_xdr(Color.green) # => "\x00\x00\x00\x01"

Color.red == ResultType.ok # => false