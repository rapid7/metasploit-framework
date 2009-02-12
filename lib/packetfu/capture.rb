
module PacketFu

	# The Capture class is used to construct PcapRub objects in order to collect
	# packets from an interface.
	#
	# This class requires PcapRub. In addition, you will need root (or root-like) privileges 
	# in order to capture from the interface.
	#
	# Note, on some wireless cards, setting :promisc => true will disable capturing.
	#
	# == Example
	#
	#  # Typical use
	#  cap = PacketFu::Capture.new(:iface => 'eth0', :promisc => true)
	#  cap.start
	#  sleep 10
	#  cap.save
	#  first_packet = cap.array[0]
	#
	#  # Tcpdump-like use
	#  cap = PacketFu::Capture.new(:start => true)
	#  cap.show_live(:save => true, :filter => 'tcp and not port 22')
	#
	# == See Also
	#
	# Read, Write
	class Capture
		attr_accessor :array, :stream # Leave these public and open.
		attr_reader :iface, :snaplen, :promisc, :timeout # Cant change after the init.

		def initialize(args={})
			@array = [] # Where the packet array goes.
			@stream = [] # Where the stream goes.
			@iface = args[:iface] || Pcap.lookupdev 
			@snaplen = args[:snaplen] || 0xffff
			@promisc = args[:promisc] || false # Sensible for some Intel wifi cards
			@timeout = args[:timeout] || 1

			setup_params(args)
		end

		def setup_params(args={})
			filter = args[:filter] # Not global; filter criteria can change.
			start = args[:start] || false
			capture if start
			bpf(:filter=>filter) if filter
		end

		# capture() initializes the @stream varaible. Valid arguments are:
		#
		#   :filter
		#     Provide a bpf filter to enable for the capture. For example, 'ip and not tcp'
		#   :start
		#     When true, start capturing packets to the @stream variable. Defaults to true
		def capture(args={})
			if Process.euid.zero?
				filter = args[:filter]
				start = args[:start] || true
				if start
					begin
						@stream = Pcap.open_live(@iface,@snaplen,@promisc,@timeout)
					rescue RuntimeError
						$stderr.print "Are you sure you're root? Error: "
						raise
					end
					bpf(:filter=>filter) if filter
				else
					@stream = []
				end
				@stream
			else
				raise RuntimeError,"Not root, so can't capture packets. Error: "
			end
		end

		# start() is equivalent to capture().
		def start(args={})
			capture(args)
		end

		# clear() clears the @stream and @array variables, essentially starting the
		# capture session over. Valid arguments are:
		#
		#   :array 
		#     If true, the @array is cleared.
		#   :stream
		#     If true, the @stream is cleared.
		def clear(args={})
			array = args[:array] || true
			stream = args[:stream] || true
			@array = [] if array
			@stream = [] if stream
		end

		# bpf() sets a bpf filter on a capture session. Valid arugments are:
		#
		#   :filter
		#     Provide a bpf filter to enable for the capture. For example, 'ip and not tcp'
		def bpf(args={})
			filter = args[:filter]
			capture if @stream.class == Array
			@stream.setfilter(filter)
		end

		# wire_to_array() saves a packet stream as an array of binary strings. From here,
		# packets may accessed by other functions. Note that the wire_to_array empties
		# the stream, so multiple calls will append new packets to @array.
		# Valid arguments are:
		#
		#   :filter
		#     Provide a bpf filter to apply to packets moving from @stream to @array.
		def wire_to_array(args={})
			filter = args[:filter] 
			bpf(:filter=>filter) if filter

			while this_pkt = @stream.next
				@array << this_pkt
			end
			@array.size
		end
		def next
			return @stream.next
		end

		# w2a() is a equivalent to wire_to_array()
		def w2a(args={})
			wire_to_array(args)
		end

		# save() is a equivalent to wire_to_array()
		def save(args={})
			wire_to_array(args)
		end

		# show_live() is a method to capture packets and display peek() data to stdout. Valid arguments are:
		#
		#   :filter
		#     Provide a bpf filter to captured packets.
		#   :save
		#     Save the capture in @array
		#   :verbose
		#     TODO: Not implemented yet; do more than just peek() at the packets.
		#   :quiet
		#     TODO: Not implemented yet; do less than peek() at the packets.
		def show_live(args={})
			filter = args[:filter]
			save = args[:save]
			verbose = args[:verbose] || args[:v] || false
			quiet = args[:quiet] || args[:q] || false # Setting q and v doesn't make a lot of sense but hey.

			# Ensure the capture's started.
			if @stream.class == Array
				capture
			end

			@stream.setfilter(filter) if filter
			while true
				@stream.each do |pkt|
					puts Packet.parse(pkt).peek
					@array << pkt if args[:save]
				end
			end
		end

	end # class Capture
end # module PacketFu
