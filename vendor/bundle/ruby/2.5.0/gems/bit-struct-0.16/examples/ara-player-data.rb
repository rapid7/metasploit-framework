class PlayerData
  class << self
    def create(*a)
      new(a.pack(FORMAT))
    end
  end

  SPEC = [
    %w( pid        i ),
    %w( x_position f ),
    %w( y_position f ),
    %w( z_position f ),
    %w( foobar     i ),
  ]

  ATTRIBUTES = SPEC.map{|s| s.first}

  FORMAT = SPEC.map{|s| s.last}.join

  SPEC.each_with_index do |spec, ix|
    at, format = spec
    eval <<-src
      def #{ at }
        @#{ at } ||= @data[#{ ix }]
      end
      def #{ at }= value
        raise TypeError unless self.#{ at }.class == value.class
        uncache
        @#{ at } = @data[#{ ix }] = value
      end
    src
  end

  def update buffer
    uncache
    @data = buffer.unpack FORMAT
  end
  alias initialize update
  def uncache
    @to_s = @to_bin = nil
  end
  def to_s
    @to_s ||= ATTRIBUTES.inject(''){|s,a| s << "#{ a } : #{ send a }, " }.chop.chop
  end
  def to_bin
    @to_bin ||= @data.pack(FORMAT)
  end
end

id, x_position, y_position, z_position, foobar =
  400, 1.0, 2.0, 3.0, 0b101010

pd = PlayerData::create id, x_position, y_position, z_position, foobar

p pd
p pd.pid
p pd.x_position
p pd.foobar
puts pd

begin
  require 'timeout'
  n = 0
  sec = 10
  Timeout::timeout(sec) do
    loop do
      PlayerData::create id, x_position, y_position, z_position, foobar
      n += 1
    end
  end
rescue Timeout::Error
  puts "creations per second : #{ n / sec }"
end

__END__

#<PlayerData:0xb7e29b7c @to_s=nil, @data=[400, 1.0, 2.0, 3.0, 42], @to_bin=nil>
400
1.0
42
pid : 400, x_position : 1.0, y_position : 2.0, z_position : 3.0, foobar : 42
creations per second : 131746
