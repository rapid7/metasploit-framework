
$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket'
require 'rex/io/ring_buffer'

#
# TODO: Mock up the socket so this test doesn't take so long
#
class Rex::IO::RingBuffer::UnitTest < Test::Unit::TestCase

	def setup
		server = Rex::Socket.create_tcp_server('LocalPort' => 0)
		lport  = server.getsockname[2]
		@client = Rex::Socket.create_tcp('PeerHost' => '127.0.0.1', 'PeerPort' => lport)
		conn   = server.accept
		#server.close		

		@r = Rex::IO::RingBuffer.new(conn, {:size => 64})
		@r.start_monitor
	end

	def teardown
		begin
			@client.close		
			@r.stop_monitor
		rescue ::Exception
		end
	end

	def test_single_read_data
		@client.put("123")
		@r.wait(0)
		s,d = @r.read_data

		assert_equal("123", d)
	end

	def test_sequential_read_data
		@r.clear_data

		s = nil
		0.upto(10) do |num|
			@client.put(num.to_s)
			@r.wait(s)
			s,d = @r.read_data(s)
			assert_equal(num.to_s, d)
		end
	end

	def test_wrap
		@r.clear_data
		0.upto(@r.size - 1) {
			@client.put("a")
			# Need to sleep so the socket doesn't get all the data in one read()
			sleep 0.05
		}
		s,d = @r.read_data

		@client.put("b")
		sleep 0.01
		s,d = @r.read_data(s)

		assert_equal("b", d)

	end

end
=begin
client.put("4")
client.put("5")
client.put("6")
s,d = r.read_data(s)

client.put("7")
client.put("8")
client.put("9")
s,d = r.read_data(s)

client.put("0")
s,d = r.read_data(s)

test_counter = 11
1.upto(100) do
	client.put( "X" )			
	test_counter += 1
end

sleep(1)

s,d = r.read_data
p s
p d

fdata = ''
File.open("/bin/ls", "rb") do |fd|
	fdata = fd.read(fd.stat.size)
	fdata = fdata * 10
	client.put(fdata)
end

sleep(1)

s,vdata = r.read_data(s)

if vdata != fdata
	puts "DATA FAILED"
else
	puts "DATA VERIFIED"
end

r.clear_data

a = r.create_stream
b = r.create_stream

client.put("ABC123")
sleep(1)

p a.read
p b.read

client.put("$$$$$$")
sleep(1)

p a.read
p b.read

c = r.create_stream
p c.read

end
=end
