require 'bit-struct'

class PlayerData < BitStruct

# type      accessor      size (bits)   description (for #inspect_detailed)
  unsigned  :pid,         32,           "Player ID"
  float     :x_position,  32,           "X position", :format => "%8.3f"
  float     :y_position,  32,           "Y position"
  float     :z_position,  32,           "Z position"
  unsigned  :foobar,      32,           "Foobar"

#  def self.create(*args)
#    new(args.pack(field_format))
#  end

end

pd = PlayerData.new(
  :pid          => 400,
  :x_position   => 1,
  :y_position   => 2,
  :z_position   => 3,
  :foobar       => 0b101010
)

p pd
p pd.pid
p pd.x_position
p pd.foobar
p String.new(pd)
puts pd.inspect_detailed

params = {
  :pid          => 400,
  :x_position   => 1,
  :y_position   => 2,
  :z_position   => 3,
  :foobar       => 0b101010
}
param_string = String.new(pd)

id, x_position, y_position, z_position, foobar =
  400, 1.0, 2.0, 3.0, 0b101010

begin
  require 'timeout'
  n = 0
  sec = 10
  Timeout::timeout(sec) do
    loop do
      PlayerData.new params
      #PlayerData.create id, x_position, y_position, z_position, foobar
      n += 1
    end
  end
rescue Timeout::Error
  puts "creations per second : #{ n / sec }"
end

__END__

#<PlayerData pid=400, x_position=1, y_position=2, z_position=3, foobar=42>
400
1
42
"\000\000\001\220\000\000\000\001\000\000\000\002\000\000\000\003\000\000\000*"
PlayerData:
                     Player ID = 400
                    X position = 1
                    Y position = 2
                    Z position = 3
                        Foobar = 42
creations per second : 22428   # using params
creations per second : 243217  # using param_string
creations per second : 94254   # using create
