require 'PcapX'
require 'getopts'

def pcapletx_usage()
  $stderr.print <<END
Usage: #{File.basename $0} [ -dnv ] [ -i interface | -r file ]
       #{' ' * File.basename($0).length} [ -c count ] [ -s snaplen ] [ filter ]
Options:
  -n  do not convert address to name
  -d  debug mode
  -v  verbose mode
END
end

module PcapX
  class PcapletX
    def usage(status, msg = nil)
      $stderr.puts msg if msg
      pcaplet_usage
      exit(status)
    end

    def initialize(args = nil)
      if args
	ARGV[0,0] = args.split(/\s+/)
      end
      usage(1) unless getopts("dnv", "i:", "r:", "c:-1", "s:68")
      $DEBUG   |= $OPT_d
      $VERBOSE |= $OPT_v

      @device = $OPT_i
      @rfile = $OPT_r
      Pcap.convert = !$OPT_n
      @count   = $OPT_c.to_i
      @snaplen = $OPT_s.to_i
      @filter = ARGV.join(' ')

      # check option consistency
      usage(1) if @device && @rfile
      if !@device and !@rfile
        @device = Pcap.lookupdev
      end

      # open
      begin
	if @device
	  @capture = Capture.open_live(@device, @snaplen)
	elsif @rfile
	  if @rfile !~ /\.gz$/
	    @capture = Capture.open_offline(@rfile)
	  else
	    $stdin = IO.popen("gzip -dc < #@rfile", 'r')
	    @capture = Capture.open_offline('-')
	  end
	end
	@capture.setfilter(@filter)
      rescue PcapError, ArgumentError
	$stdout.flush
	$stderr.puts $!
	exit(1)
      end
    end

    attr('capture')

    def add_filter(f)
      if @filter == nil || @filter =~ /^\s*$/  # if empty
	@filter = f
      else
	f = f.source if f.is_a? Filter
	@filter = "( #{@filter} ) and ( #{f} )"
      end
      @capture.setfilter(@filter)
    end

    def each_packet(&block)
      begin
	duplicated = (RUBY_PLATFORM =~ /linux/ && @device == "lo")
        unless duplicated
          @capture.loop(@count, &block)
        else
          flip = true
          @capture.loop(@count) do |pkt|
            flip = (! flip)
            next if flip
            block.call pkt
          end
        end
      rescue Interrupt
        $stdout.flush
        $stderr.puts("Interrupted.")
        $stderr.puts $@.join("\n\t") if $DEBUG
      ensure
	# print statistics if live
	if @device
	  stat = @capture.stats
	  if stat
	    $stderr.print("#{stat.recv} packets received by filter\n");
	    $stderr.print("#{stat.drop} packets dropped by kernel\n");
	  end
	end
      end
    end

    alias each each_packet

    def close
      @capture.close
    end
  end
end

PcapletX = Pcap::PcapletX
