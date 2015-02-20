# -*- coding: binary -*-
#
#       $Id: Resolver.rb,v 1.11 2006/07/30 16:55:35 bluemonk Exp $
#



require 'socket'
require 'timeout'
require 'ipaddr'
require 'logger'
require 'net/dns/packet'
require 'net/dns/resolver/timeouts'

alias old_send send

module Net # :nodoc:
  module DNS

    include Logger::Severity

    # =Name
    #
    # Net::DNS::Resolver - DNS resolver class
    #
    # =Synopsis
    #
    #    require 'net/dns/resolver'
    #
    # =Description
    #
    # The Net::DNS::Resolver class implements a complete DNS resolver written
    # in pure Ruby, without a single C line of code. It has all of the
    # tipical properties of an evoluted resolver, and a bit of OO which
    # comes from having used Ruby.
    #
    # This project started as a porting of the Net::DNS Perl module,
    # written by Martin Fuhr, but turned out (in the last months) to be
    # an almost complete rewriting. Well, maybe some of the features of
    # the Perl version are still missing, but guys, at least this is
    # readable code!
    #
    # FIXME
    #
    # =Environment
    #
    # The Following Environment variables can also be used to configure
    # the resolver:
    #
    # * +RES_NAMESERVERS+: A space-separated list of nameservers to query.
    #
    #      # Bourne Shell
    #      $ RES_NAMESERVERS="192.168.1.1 192.168.2.2 192.168.3.3"
    #      $ export RES_NAMESERVERS
    #
    #      # C Shell
    #      % setenv RES_NAMESERVERS "192.168.1.1 192.168.2.2 192.168.3.3"
    #
    # * +RES_SEARCHLIST+: A space-separated list of domains to put in the
    #   search list.
    #
    #      # Bourne Shell
    #      $ RES_SEARCHLIST="example.com sub1.example.com sub2.example.com"
    #      $ export RES_SEARCHLIST
    #
    #      # C Shell
    #      % setenv RES_SEARCHLIST "example.com sub1.example.com sub2.example.com"
    #
    # * +LOCALDOMAIN+: The default domain.
    #
    #      # Bourne Shell
    #      $ LOCALDOMAIN=example.com
    #      $ export LOCALDOMAIN
    #
    #      # C Shell
    #      % setenv LOCALDOMAIN example.com
    #
    # * +RES_OPTIONS+: A space-separated list of resolver options to set.
    #   Options that take values are specified as option:value.
    #
    #      # Bourne Shell
    #      $ RES_OPTIONS="retrans:3 retry:2 debug"
    #      $ export RES_OPTIONS
    #
    #      # C Shell
    #      % setenv RES_OPTIONS "retrans:3 retry:2 debug"
    #
    class Resolver

      # An hash with the defaults values of almost all the
      # configuration parameters of a resolver object. See
      # the description for each parameter to have an
      # explanation of its usage.
      Defaults = {
        :config_file => "/etc/resolv.conf",
        :log_file => $stdout,
        :port => 53,
        :searchlist => [],
        :nameservers => [IPAddr.new("127.0.0.1")],
        :domain => "",
        :source_port => 0,
        :source_address => IPAddr.new("0.0.0.0"),
        :retry_interval => 5,
        :retry_number => 4,
        :recursive => true,
        :defname => true,
        :dns_search => true,
        :use_tcp => false,
        :ignore_truncated => false,
        :packet_size => 512,
        :tcp_timeout => TcpTimeout.new(120),
        :udp_timeout => UdpTimeout.new(0)}

      # Create a new resolver object.
      #
      # Argument +config+ can either be empty or be an hash with
      # some configuration parameters. To know what each parameter
      # do, look at the description of each.
      # Some example:
      #
      #   # Use the sistem defaults
      #   res = Net::DNS::Resolver.new
      #
      #   # Specify a configuration file
      #   res = Net::DNS::Resolver.new(:config_file => '/my/dns.conf')
      #
      #   # Set some option
      #   res = Net::DNS::Resolver.new(:nameservers => "172.16.1.1",
      #                                :recursive => false,
      #                                :retry => 10)
      #
      # ===Config file
      #
      # Net::DNS::Resolver uses a config file to read the usual
      # values a resolver needs, such as nameserver list and
      # domain names. On UNIX systems the defaults are read from the
      # following files, in the order indicated:
      #
      # * /etc/resolv.conf
      # * $HOME/.resolv.conf
      # * ./.resolv.conf
      #
      # The following keywords are recognized in resolver configuration files:
      #
      # * domain: the default domain.
      # * search: a space-separated list of domains to put in the search list.
      # * nameserver: a space-separated list of nameservers to query.
      #
      # Files except for /etc/resolv.conf must be owned by the effective userid
      # running the program or they won't be read.  In addition, several environment
      # variables can also contain configuration information; see Environment
      # in the main description for Resolver class.
      #
      # On Windows Systems, an attempt is made to determine the system defaults
      # using the registry.  This is still a work in progress; systems with many
      # dynamically configured network interfaces may confuse Net::DNS.
      #
      # You can include a configuration file of your own when creating a resolver
      # object:
      #
      #   # Use my own configuration file
      #   my $res = Net::DNS::Resolver->new(config_file => '/my/dns.conf');
      #
      # This is supported on both UNIX and Windows.  Values pulled from a custom
      # configuration file override the the system's defaults, but can still be
      # overridden by the other arguments to Resolver::new.
      #
      # Explicit arguments to Resolver::new override both the system's defaults
      # and the values of the custom configuration file, if any.
      #
      # ===Parameters
      #
      # The following arguments to Resolver::new are supported:
      #
      # - nameservers: an array reference of nameservers to query.
      # - searchlist:  an array reference of domains.
      # - recurse
      # - debug
      # - domain
      # - port
      # - srcaddr
      # - srcport
      # - tcp_timeout
      # - udp_timeout
      # - retrans
      # - retry
      # - usevc
      # - stayopen
      # - igntc
      # - defnames
      # - dnsrch
      # - persistent_tcp
      # - persistent_udp
      # - dnssec
      #
      # For more information on any of these options, please consult the
      # method of the same name.
      #
      # ===Disclaimer
      #
      # Part of the above documentation is taken from the one in the
      # Net::DNS::Resolver Perl module.
      #
      def initialize(config = {})
        raise ResolverArgumentError, "Argument has to be Hash" unless config.kind_of? Hash
        # config.key_downcase!
        @config = Defaults.merge config
        @raw = false

        # New logger facility
        @logger = Logger.new(@config[:log_file])
        @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN

        #------------------------------------------------------------
        # Resolver configuration will be set in order from:
        # 1) initialize arguments
        # 2) ENV variables
        # 3) config file
        # 4) defaults (and /etc/resolv.conf for config)
        #------------------------------------------------------------



        #------------------------------------------------------------
        # Parsing config file
        #------------------------------------------------------------
        parse_config_file

        #------------------------------------------------------------
        # Parsing ENV variables
        #------------------------------------------------------------
        parse_environment_variables

        #------------------------------------------------------------
        # Parsing arguments
        #------------------------------------------------------------
        config.each do |key,val|
          next if key == :log_file or key == :config_file
          begin
            eval "self.#{key.to_s} = val"
          rescue NoMethodError
            raise ResolverArgumentError, "Option #{key} not valid"
          end
        end
      end

      # Get the resolver searchlist, returned as an array of entries
      #
      #   res.searchlist
      #     #=> ["example.com","a.example.com","b.example.com"]
      #
      def searchlist
        @config[:searchlist].inspect
      end

      # Set the resolver searchlist.
      # +arg+ can be a single string or an array of strings
      #
      #   res.searchstring = "example.com"
      #   res.searchstring = ["example.com","a.example.com","b.example.com"]
      #
      # Note that you can also append a new name to the searchlist
      #
      #   res.searchlist << "c.example.com"
      #   res.searchlist
      #     #=> ["example.com","a.example.com","b.example.com","c.example.com"]
      #
      # The default is an empty array
      #
      def searchlist=(arg)
        case arg
        when String
          @config[:searchlist] = [arg] if valid? arg
          @logger.info "Searchlist changed to value #{@config[:searchlist].inspect}"
        when Array
          @config[:searchlist] = arg if arg.all? {|x| valid? x}
          @logger.info "Searchlist changed to value #{@config[:searchlist].inspect}"
        else
          raise ResolverArgumentError, "Wrong argument format, neither String nor Array"
        end
      end

      # Get the list of resolver nameservers, in a dotted decimal format
      #
      #   res.nameservers
      #     #=> ["192.168.0.1","192.168.0.2"]
      #
      def nameservers
        arr = []
        @config[:nameservers].each do |x|
          arr << x.to_s
        end
        arr
      end
      alias_method :nameserver, :nameservers

      # Set the list of resolver nameservers
      # +arg+ can be a single ip address or an array of addresses
      #
      #   res.nameservers = "192.168.0.1"
      #   res.nameservers = ["192.168.0.1","192.168.0.2"]
      #
      # If you want you can specify the addresses as IPAddr instances
      #
      #   ip = IPAddr.new("192.168.0.3")
      #   res.nameservers << ip
      #     #=> ["192.168.0.1","192.168.0.2","192.168.0.3"]
      #
      # The default is 127.0.0.1 (localhost)
      #
      def nameservers=(arg)
        case arg
        when String
          begin
            @config[:nameservers] = [IPAddr.new(arg)]
            @logger.info "Nameservers list changed to value #{@config[:nameservers].inspect}"
          rescue ArgumentError # arg is in the name form, not IP
            nameservers_from_name(arg)
          end
        when IPAddr
          @config[:nameservers] = [arg]
          @logger.info "Nameservers list changed to value #{@config[:nameservers].inspect}"
        when Array
          @config[:nameservers] = []
          arg.each do |x|
            @config[:nameservers] << case x
                                     when String
                                       begin
                                         IPAddr.new(x)
                                       rescue ArgumentError
                                         nameservers_from_name(arg)
                                         return
                                       end
                                     when IPAddr
                                       x
                                     else
                                       raise ResolverArgumentError, "Wrong argument format"
                                     end
          end
          @logger.info "Nameservers list changed to value #{@config[:nameservers].inspect}"
        else
          raise ResolverArgumentError, "Wrong argument format, neither String, Array nor IPAddr"
        end
      end
      alias_method("nameserver=","nameservers=")

      # Return a string with the default domain
      #
      def domain
        @config[:domain].inspect
      end

      # Set the domain for the query
      #
      def domain=(name)
        @config[:domain] = name if valid? name
      end

      # Return the defined size of the packet
      #
      def packet_size
        @config[:packet_size]
      end

      # Get the port number to which the resolver sends queries.
      #
      #   puts "Sending queries to port #{res.port}"
      #
      def port
        @config[:port]
      end

      # Set the port number to which the resolver sends queries.  This can be useful
      # for testing a nameserver running on a non-standard port.
      #
      #   res.port = 10053
      #
      # The default is port 53.
      #
      def port=(num)
        if (0..65535).include? num
          @config[:port] = num
          @logger.info "Port number changed to #{num}"
        else
          raise ResolverArgumentError, "Wrong port number #{num}"
        end
      end

      # Get the value of the source port number
      #
      #   puts "Sending queries using port #{res.source_port}"
      #
      def source_port
        @config[:source_port]
      end
      alias srcport source_port

      # Set the local source port from which the resolver sends its queries.
      #
      #   res.source_port = 40000
      #
      # Note that if you want to set a port you need root priviledges, as
      # raw sockets will be used to generate packets. The class will then
      # generate the exception ResolverPermissionError if you're not root.
      #
      # The default is 0, which means that the port will be chosen by the
      # underlaying layers.
      #
      def source_port=(num)
        unless root?
          raise ResolverPermissionError, "Are you root?"
        end
        if (0..65535).include?(num)
          @config[:source_port] = num
        else
          raise ResolverArgumentError, "Wrong port number #{num}"
        end
      end
      alias srcport= source_port=

      # Get the local address from which the resolver sends queries
      #
      #   puts "Sending queries using source address #{res.source_address}"
      #
      def source_address
        @config[:source_address].to_s
      end
      alias srcaddr source_address

      # Set the local source address from which the resolver sends its
      # queries.
      #
      #   res.source_address = "172.16.100.1"
      #   res.source_address = IPAddr.new("172.16.100.1")
      #
      # You can specify +arg+ as either a string containing the ip address
      # or an instance of IPAddr class.
      #
      # Normally this can be used to force queries out a specific interface
      # on a multi-homed host. In this case, you should of course need to
      # know the addresses of the interfaces.
      #
      # Another way to use this option is for some kind of spoofing attacks
      # towards weak nameservers, to probe the security of your network.
      # This includes specifing ranged attacks such as DoS and others. For
      # a paper on DNS security, checks http://www.marcoceresa.com/security/
      #
      # Note that if you want to set a non-binded source address you need
      # root priviledges, as raw sockets will be used to generate packets.
      # The class will then generate an exception if you're not root.
      #
      # The default is 0.0.0.0, meaning any local address (chosen on routing
      # needs).
      #
      def source_address=(addr)
        unless addr.respond_to? :to_s
          raise ResolverArgumentError, "Wrong address argument #{addr}"
        end

        begin
          port = rand(64000)+1024
          @logger.warn "Try to determine state of source address #{addr} with port #{port}"
          a = TCPServer.new(addr.to_s,port)
        rescue SystemCallError => e
          case e.errno
          when 98 # Port already in use!
            @logger.warn "Port already in use"
            retry
          when 99 # Address is not valid: raw socket
            @raw = true
            @logger.warn "Using raw sockets"
          else
            raise SystemCallError, e
          end
        ensure
          a.close
        end

        case addr
        when String
          @config[:source_address] = IPAddr.new(string)
          @logger.info "Using new source address: #{@config[:source_address]}"
        when IPAddr
          @config[:source_address] = addr
          @logger.info "Using new source address: #{@config[:source_address]}"
        else
          raise ArgumentError, "Unknown dest_address format"
        end
      end
      alias srcaddr= source_address=

      # Return the retrasmission interval (in seconds) the resolvers has
      # been set on
      #
      def retry_interval
        @config[:retry_interval]
      end
      alias retrans retry_interval

      # Set the retrasmission interval in seconds. Default 5 seconds
      #
      def retry_interval=(num)
        if num > 0
          @config[:retry_interval] = num
          @logger.info "Retransmission interval changed to #{num} seconds"
        else
          raise ResolverArgumentError, "Interval must be positive"
        end
      end
      alias retrans= retry_interval=

      # The number of times the resolver will try a query
      #
      #   puts "Will try a max of #{res.retry_number} queries"
      #
      def retry_number
        @config[:retry_number]
      end

      # Set the number of times the resolver will try a query.
      # Default 4 times
      #
      def retry_number=(num)
        if num.kind_of? Integer and num > 0
          @config[:retry_number] = num
          @logger.info "Retrasmissions number changed to #{num}"
        else
          raise ResolverArgumentError, "Retry value must be a positive integer"
        end
      end
      alias_method('retry=', 'retry_number=')

      # This method will return true if the resolver is configured to
      # perform recursive queries.
      #
      #   print "The resolver will perform a "
      #   print res.recursive? ? "" : "not "
      #   puts "recursive query"
      #
      def recursive?
        @config[:recursive]
      end
      alias_method :recurse, :recursive?
      alias_method :recursive, :recursive?

      # Sets whether or not the resolver should perform recursive
      # queries. Default is true.
      #
      #   res.recursive = false # perform non-recursive query
      #
      def recursive=(bool)
        case bool
        when TrueClass,FalseClass
          @config[:recursive] = bool
          @logger.info("Recursive state changed to #{bool}")
        else
          raise ResolverArgumentError, "Argument must be boolean"
        end
      end
      alias_method :recurse=, :recursive=

      # Return a string rapresenting the resolver state, suitable
      # for printing on the screen.
      #
      #   puts "Resolver state:"
      #   puts res.state
      #
      def state
        str = ";; RESOLVER state:\n;; "
        i = 1
        @config.each do |key,val|
          if key == :log_file or key == :config_file
            str << "#{key}: #{val} \t"
            else
            str << "#{key}: #{eval(key.to_s)} \t"
          end
          str << "\n;; " if i % 2 == 0
          i += 1
        end
        str
      end
      alias print state
      alias inspect state

      # Checks whether the +defname+ flag has been activate.
      def defname?
        @config[:defname]
      end
      alias defname defname?

      # Set the flag +defname+ in a boolean state. if +defname+ is true,
      # calls to Resolver#query will append the default domain to names
      # that contain no dots.
      # Example:
      #
      #   # Domain example.com
      #   res.defname = true
      #   res.query("machine1")
      #     #=> This will perform a query for machine1.example.com
      #
      # Default is true.
      #
      def defname=(bool)
        case bool
        when TrueClass,FalseClass
          @config[:defname] = bool
          @logger.info("Defname state changed to #{bool}")
        else
          raise ResolverArgumentError, "Argument must be boolean"
        end
      end

      # Get the state of the dns_search flag
      def dns_search
        @config[:dns_search]
      end
      alias_method :dnsrch, :dns_search

      # Set the flag +dns_search+ in a boolean state. If +dns_search+
      # is true, when using the Resolver#search method will be applied
      # the search list. Default is true.
      #
      def dns_search=(bool)
        case bool
        when TrueClass,FalseClass
          @config[:dns_search] = bool
          @logger.info("DNS search state changed to #{bool}")
        else
          raise ResolverArgumentError, "Argument must be boolean"
        end
      end
      alias_method("dnsrch=","dns_search=")

      # Get the state of the use_tcp flag.
      #
      def use_tcp?
        @config[:use_tcp]
      end
      alias_method :usevc, :use_tcp?
      alias_method :use_tcp, :use_tcp?

      # If +use_tcp+ is true, the resolver will perform all queries
      # using TCP virtual circuits instead of UDP datagrams, which
      # is the default for the DNS protocol.
      #
      #   res.use_tcp = true
      #   res.query "host.example.com"
      #     #=> Sending TCP segments...
      #
      # Default is false.
      #
      def use_tcp=(bool)
        case bool
        when TrueClass,FalseClass
          @config[:use_tcp] = bool
          @logger.info("Use tcp flag changed to #{bool}")
        else
          raise ResolverArgumentError, "Argument must be boolean"
        end
      end
      alias usevc= use_tcp=

      def ignore_truncated?
        @config[:ignore_truncated]
      end
      alias_method :ignore_truncated, :ignore_truncated?

      def ignore_truncated=(bool)
        case bool
        when TrueClass,FalseClass
          @config[:ignore_truncated] = bool
          @logger.info("Ignore truncated flag changed to #{bool}")
        else
          raise ResolverArgumentError, "Argument must be boolean"
        end
      end

      # Return an object representing the value of the stored TCP
      # timeout the resolver will use in is queries. This object
      # is an instance of the class +TcpTimeout+, and two methods
      # are available for printing informations: TcpTimeout#to_s
      # and TcpTimeout#pretty_to_s.
      #
      # Here's some example:
      #
      #   puts "Timeout of #{res.tcp_timeout} seconds" # implicit to_s
      #     #=> Timeout of 150 seconds
      #
      #   puts "You set a timeout of " + res.tcp_timeout.pretty_to_s
      #     #=> You set a timeout of 2 minutes and 30 seconds
      #
      # If the timeout is infinite, a string "infinite" will
      # be returned.
      #
      def tcp_timeout
        @config[:tcp_timeout].to_s
      end

      # Set the value of TCP timeout for resolver queries that
      # will be performed using TCP. A value of 0 means that
      # the timeout will be infinite.
      # The value is stored internally as a +TcpTimeout+ object, see
      # the description for Resolver#tcp_timeout
      #
      # Default is 120 seconds
      def tcp_timeout=(secs)
        @config[:tcp_timeout] = TcpTimeout.new(secs)
        @logger.info("New TCP timeout value: #{@config[:tcp_timeout]} seconds")
      end

      # Return an object representing the value of the stored UDP
      # timeout the resolver will use in is queries. This object
      # is an instance of the class +UdpTimeout+, and two methods
      # are available for printing informations: UdpTimeout#to_s
      # and UdpTimeout#pretty_to_s.
      #
      # Here's some example:
      #
      #   puts "Timeout of #{res.udp_timeout} seconds" # implicit to_s
      #     #=> Timeout of 150 seconds
      #
      #   puts "You set a timeout of " + res.udp_timeout.pretty_to_s
      #     #=> You set a timeout of 2 minutes and 30 seconds
      #
      # If the timeout is zero, a string "not defined" will
      # be returned.
      #
      def udp_timeout
        @config[:udp_timeout].to_s
      end

      # Set the value of UDP timeout for resolver queries that
      # will be performed using UDP. A value of 0 means that
      # the timeout will not be used, and the resolver will use
      # only +retry_number+ and +retry_interval+ parameters.
      # That is the default.
      #
      # The value is stored internally as a +UdpTimeout+ object, see
      # the description for Resolver#udp_timeout
      #
      def udp_timeout=(secs)
        @config[:udp_timeout] = UdpTimeout.new(secs)
        @logger.info("New UDP timeout value: #{@config[:udp_timeout]} seconds")
      end

      # Set a new log file for the logger facility of the resolver
      # class. Could be a file descriptor too:
      #
      #   res.log_file = $stderr
      #
      # Note that a new logging facility will be create, destroing
      # the old one, which will then be impossibile to recover.
      #
      def log_file=(log)
        @logger.close
        @config[:log_file] = log
        @logger = Logger.new(@config[:log_file])
        @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN
      end

      # This one permits to have a personal logger facility to handle
      # resolver messages, instead of new built-in one, which is set up
      # for a +$stdout+ (or +$stderr+) use.
      #
      # If you want your own logging facility you can create a new instance
      # of the +Logger+ class:
      #
      #   log = Logger.new("/tmp/resolver.log","weekly",2*1024*1024)
      #   log.level = Logger::DEBUG
      #   log.progname = "ruby_resolver"
      #
      # and then pass it to the resolver:
      #
      #   res.logger = log
      #
      # Note that this will destroy the precedent logger.
      #
      def logger=(logger)
        if logger.kind_of? Logger
          @logger.close
          @logger = logger
        else
          raise ResolverArgumentError, "Argument must be an instance of Logger class"
        end
      end

      # Set the log level for the built-in logging facility.
      #
      # The log level can be one of the following:
      #
      # - +Net::DNS::DEBUG+
      # - +Net::DNS::INFO+
      # - +Net::DNS::WARN+
      # - +Net::DNS::ERROR+
      # - +Net::DNS::FATAL+
      #
      # Note that if the global variable $DEBUG is set (like when the
      # -d switch is used at the command line) the logger level is
      # automatically set at DEGUB.
      #
      # For further informations, see Logger documentation in the
      # Ruby standard library.
      #
      def log_level=(level)
        @logger.level = level
      end

      # Performs a DNS query for the given name, applying the searchlist if
      # appropriate.  The search algorithm is as follows:
      #
      # 1. If the name contains at least one dot, try it as is.
      # 2. If the name doesn't end in a dot then append each item in the search
      #    list to the name.  This is only done if +dns_search+ is true.
      # 3. If the name doesn't contain any dots, try it as is.
      #
      # The record type and class can be omitted; they default to +A+ and +IN+.
      #
      #   packet = res.search('mailhost')
      #   packet = res.search('mailhost.example.com')
      #   packet = res.search('example.com', Net::DNS::MX)
      #   packet = res.search('user.passwd.example.com', Net::DNS::TXT, Net::DNS::HS)
      #
      # If the name is an IP address (Ipv4 or IPv6), in the form of a string
      # or a +IPAddr+ object, then an appropriate PTR query will be performed:
      #
      #   ip = IPAddr.new("172.16.100.2")
      #   packet = res.search(ip)
      #   packet = res.search("192.168.10.254")
      #
      # Returns a Net::DNS::Packet object. If you need to examine the response packet
      # whether it contains any answers or not, use the send() method instead.
      #
      def search(name,type=Net::DNS::A,cls=Net::DNS::IN)

        # If the name contains at least one dot then try it as is first.
        if name.include? "."
          @logger.debug "Search(#{name},#{Net::DNS::RR::Types.new(type)},#{Net::DNS::RR::Classes.new(cls)})"
          ans = query(name,type,cls)
          return ans if ans.header.anCount > 0
        end

        # If the name doesn't end in a dot then apply the search list.
        if name !~ /\.$/ and @config[:dns_search]
          @config[:searchlist].each do |domain|
            newname = name + "." + domain
            @logger.debug "Search(#{newname},#{Net::DNS::RR::Types.new(type)},#{Net::DNS::RR::Classes.new(cls)})"
            ans = query(newname,type,cls)
            return ans if ans.header.anCount > 0
          end
        end

        # Finally, if the name has no dots then try it as is.
        @logger.debug "Search(#{name},#{Net::DNS::RR::Types.new(type)},#{Net::DNS::RR::Classes.new(cls)})"
        query(name+".",type,cls)

      end

      # Performs a DNS query for the given name; the search list
      # is not applied.  If the name doesn't contain any dots and
      # +defname+ is true then the default domain will be appended.
      #
      # The record type and class can be omitted; they default to +A+
      # and +IN+.  If the name looks like an IP address (IPv4 or IPv6),
      # then an appropriate PTR query will be performed.
      #
      #   packet = res.query('mailhost')
      #   packet = res.query('mailhost.example.com')
      #   packet = res.query('example.com', Net::DNS::MX)
      #   packet = res.query('user.passwd.example.com', Net::DNS::TXT, Net::DNS::HS)
      #
      # If the name is an IP address (Ipv4 or IPv6), in the form of a string
      # or a +IPAddr+ object, then an appropriate PTR query will be performed:
      #
      #   ip = IPAddr.new("172.16.100.2")
      #   packet = res.query(ip)
      #   packet = res.query("192.168.10.254")
      #
      # Returns a Net::DNS::Packet object. If you need to examine the response
      # packet whether it contains any answers or not, use the Resolver#send
      # method instead.
      #
      def query(name,type=Net::DNS::A,cls=Net::DNS::IN)

        # If the name doesn't contain any dots then append the default domain.
        if name !~ /\./ and name !~ /:/ and @config[:defnames]
          name += "." + @config[:domain]
        end

        @logger.debug "Query(#{name},#{Net::DNS::RR::Types.new(type)},#{Net::DNS::RR::Classes.new(cls)})"

        send(name,type,cls)

      end

      # Performs a DNS query for the given name.  Neither the
      # searchlist nor the default domain will be appended.
      #
      # The argument list can be either a Net::DNS::Packet object
      # or a name string plus optional type and class, which if
      # omitted default to +A+ and +IN+.
      #
      # Returns a Net::DNS::Packet object.
      #
      #   # Sending a +Packet+ object
      #   send_packet = Net::DNS::Packet.new("host.example.com",Net::DNS::NS,Net::DNS::HS)
      #   packet = res.send(send_packet)
      #
      #   # Performing a query
      #   packet = res.send("host.example.com")
      #   packet = res.send("host.example.com",Net::DNS::NS)
      #   packet = res.send("host.example.com",Net::DNS::NS,Net::DNS::HS)
      #
      # If the name is an IP address (Ipv4 or IPv6), in the form of a string
      # or a IPAddr object, then an appropriate PTR query will be performed:
      #
      #   ip = IPAddr.new("172.16.100.2")
      #   packet = res.send(ip)
      #   packet = res.send("192.168.10.254")
      #
      # Use +packet.header.ancount+ or +packet.answer+ to find out if there
      # were any records in the answer section.
      #
      def send(argument,type=Net::DNS::A,cls=Net::DNS::IN)
        if @config[:nameservers].size == 0
          raise ResolverError, "No nameservers specified!"
        end

        method = :send_udp

        if argument.kind_of? Net::DNS::Packet
          packet = argument
        else
          packet = make_query_packet(argument,type,cls)
        end

        # Store packet_data for performance improvements,
        # so methods don't keep on calling Packet#data
        packet_data = packet.data
        packet_size = packet_data.size

        # Choose whether use TCP, UDP or RAW
        if packet_size > @config[:packet_size] # Must use TCP, either plain or raw
          if @raw # Use raw sockets?
            @logger.info "Sending #{packet_size} bytes using TCP over RAW socket"
            method = :send_raw_tcp
          else
            @logger.info "Sending #{packet_size} bytes using TCP"
            method = :send_tcp
          end
        else # Packet size is inside the boundaries
          if @raw # Use raw sockets?
            @logger.info "Sending #{packet_size} bytes using UDP over RAW socket"
            method = :send_raw_udp
          elsif use_tcp? # User requested TCP
            @logger.info "Sending #{packet_size} bytes using TCP"
            method = :send_tcp
          else # Finally use UDP
            @logger.info "Sending #{packet_size} bytes using UDP"
          end
        end

        if type == Net::DNS::AXFR
          if @raw
            @logger.warn "AXFR query, switching to TCP over RAW socket"
            method = :send_raw_tcp
          else
            @logger.warn "AXFR query, switching to TCP"
            method = :send_tcp
          end
        end

        ans = self.old_send(method,packet,packet_data)

        unless ans
          @logger.fatal "No response from nameservers list: aborting"
          raise NoResponseError
        end

        @logger.info "Received #{ans[0].size} bytes from #{ans[1][2]+":"+ans[1][1].to_s}"
        response = Net::DNS::Packet.parse(ans[0],ans[1])

        if response.header.truncated? and not ignore_truncated?
          @logger.warn "Packet truncated, retrying using TCP"
          self.use_tcp = true
          begin
            return send(argument,type,cls)
          ensure
            self.use_tcp = false
          end
        end

        return response
      end

      #
      # Performs a zone transfer for the zone passed as a parameter.
      #
    # Returns a list of Net::DNS::Packet (not answers!)
      #
      def axfr(name,cls=Net::DNS::IN)
        @logger.info "Requested AXFR transfer, zone #{name} class #{cls}"
        if @config[:nameservers].size == 0
          raise ResolverError, "No nameservers specified!"
        end

        method = :send_tcp
        packet = make_query_packet(name, Net::DNS::AXFR, cls)

        # Store packet_data for performance improvements,
        # so methods don't keep on calling Packet#data
        packet_data = packet.data
        packet_size = packet_data.size

    if @raw
      @logger.warn "AXFR query, switching to TCP over RAW socket"
      method = :send_raw_tcp
    else
      @logger.warn "AXFR query, switching to TCP"
      method = :send_tcp
    end

        answers = []
        soa = 0
        self.old_send(method, packet, packet_data) do |ans|
          @logger.info "Received #{ans[0].size} bytes from #{ans[1][2]+":"+ans[1][1].to_s}"

          begin
            response = Net::DNS::Packet.parse(ans[0],ans[1])
            if response.answer[0].type == "SOA"
              soa += 1
              if soa >= 2
                break
              end
            end
            answers << response
          rescue NameError => e
            @logger.warn "Error parsing axfr response: #{e.message}"
          end
        end
        if answers.empty?
          @logger.fatal "No response from nameservers list: aborting"
          raise NoResponseError
        end

        return answers
      end

      #
      # Performs an MX query for the domain name passed as parameter.
      #
      # It actually uses the same methods a normal Resolver query would
      # use, but automatically sort the results based on preferences
      # and returns an ordered array.
      #
      # Example:
      #
      #   res = Net::DNS::Resolver.new
      #   res.mx("google.com")
      #
      def mx(name,cls=Net::DNS::IN)
        arr = []
        send(name, Net::DNS::MX, cls).answer.each do |entry|
          arr << entry if entry.type == 'MX'
        end
        return arr.sort_by {|a| a.preference}
      end

      private

      # Parse a configuration file specified as the argument.
      #
      def parse_config_file
        if RUBY_PLATFORM =~ /mswin32|cygwin|mingw|bccwin/
          require 'win32/resolv'
          arr = Win32::Resolv.get_resolv_info
          self.domain = arr[0]
          self.nameservers = arr[1]
        else
          IO.foreach(@config[:config_file]) do |line|
            line.gsub!(/\s*[;#].*/,"")
            next unless line =~ /\S/
            case line
            when /^\s*domain\s+(\S+)/
              self.domain = $1
            when /^\s*search\s+(.*)/
              self.searchlist = $1.split(" ")
            when /^\s*nameserver\s+(.*)/
              self.nameservers = $1.split(" ")
            end
          end
        end
      end

      # Parse environment variables
      def parse_environment_variables
        if ENV['RES_NAMESERVERS']
          self.nameservers = ENV['RES_NAMESERVERS'].split(" ")
        end
        if ENV['RES_SEARCHLIST']
          self.searchlist = ENV['RES_SEARCHLIST'].split(" ")
        end
        if ENV['LOCALDOMAIN']
          self.domain = ENV['LOCALDOMAIN']
        end
        if ENV['RES_OPTIONS']
          ENV['RES_OPTIONS'].split(" ").each do |opt|
            name,val = opt.split(":")
            begin
              eval("self.#{name} = #{val}")
            rescue NoMethodError
              raise ResolverArgumentError, "Invalid ENV option #{name}"
            end
          end
        end
      end

      def nameservers_from_name(arg)
        arr = []
        arg.split(" ").each do |name|
          Resolver.new.search(name).each_address do |ip|
            arr << ip
          end
        end
        @config[:nameservers] << arr
      end

      def make_query_packet(string,type,cls)
        case string
        when IPAddr
          name = string.reverse
          type = Net::DNS::PTR
          @logger.warn "PTR query required for address #{string}, changing type to PTR"
        when /\d/ # Contains a number, try to see if it's an IP or IPv6 address
          begin
            name = IPAddr.new(string).reverse
            type = Net::DNS::PTR
          rescue ArgumentError
            name = string if valid? string
          end
        else
          name = string if valid? string
        end

        # Create the packet
        packet = Net::DNS::Packet.new(name,type,cls)

        if packet.query?
          packet.header.recursive = @config[:recursive] ? 1 : 0
        end

        # DNSSEC and TSIG stuff to be inserted here

        packet

      end

      def send_tcp(packet,packet_data)

        ans = nil
        length = [packet_data.size].pack("n")

        @config[:nameservers].each do |ns|
          begin
            socket = Socket.new(Socket::AF_INET,Socket::SOCK_STREAM,0)
            socket.bind(Socket.pack_sockaddr_in(@config[:source_port],@config[:source_address].to_s))

            sockaddr = Socket.pack_sockaddr_in(@config[:port],ns.to_s)

            @config[:tcp_timeout].timeout do
              catch "next nameserver" do
                socket.connect(sockaddr)
                @logger.info "Contacting nameserver #{ns} port #{@config[:port]}"
                socket.write(length+packet_data)
                got_something = false
                loop do
                  buffer = ""
                  ans = socket.recv(Net::DNS::INT16SZ)
                  if ans.size == 0
                    if got_something
                      break #Proper exit from loop
                    else
                      @logger.warn "Connection reset to nameserver #{ns}, trying next."
                      throw "next nameserver"
                    end
                  end
                  got_something = true
                  len = ans.unpack("n")[0]

                  @logger.info "Receiving #{len} bytes..."

                  if len == 0
                    @logger.warn "Receiving 0 length packet from nameserver #{ns}, trying next."
                    throw "next nameserver"
                  end

                  while (buffer.size < len)
                    left = len - buffer.size
                    temp,from = socket.recvfrom(left)
                    buffer += temp
                  end

                  unless buffer.size == len
                    @logger.warn "Malformed packet from nameserver #{ns}, trying next."
                    throw "next nameserver"
                  end
                  if block_given?
                    yield [buffer,["",@config[:port],ns.to_s,ns.to_s]]
                  else
                    return [buffer,["",@config[:port],ns.to_s,ns.to_s]]
                  end
                end
              end
            end
          rescue Timeout::Error
            @logger.warn "Nameserver #{ns} not responding within TCP timeout, trying next one"
            next
          ensure
            socket.close
          end
        end
        return nil
      end

      def send_udp(packet,packet_data)
        socket = UDPSocket.new
        socket.bind(@config[:source_address].to_s,@config[:source_port])

        ans = nil
        response = ""
        @config[:nameservers].each do |ns|
          begin
            @config[:udp_timeout].timeout do
              @logger.info "Contacting nameserver #{ns} port #{@config[:port]}"
              socket.send(packet_data,0,ns.to_s,@config[:port])
              ans = socket.recvfrom(@config[:packet_size])
            end
            break if ans
          rescue Timeout::Error
            @logger.warn "Nameserver #{ns} not responding within UDP timeout, trying next one"
            next
          end
        end
        ans
      end

      def valid?(name)
        if name =~ /[^-\w\.]/
          raise ResolverArgumentError, "Invalid domain name #{name}"
        else
          true
        end
      end

    end # class Resolver
  end # module DNS
end # module Net

class ResolverError < ArgumentError # :nodoc:
end
class ResolverArgumentError < ArgumentError # :nodoc:
end
class NoResponseError < StandardError # :nodoc:
end

module ExtendHash # :nodoc:
  # Returns an hash with all the
  # keys turned into downcase
  #
  #   hsh = {"Test" => 1, "FooBar" => 2}
  #   hsh.key_downcase!
  #      #=> {"test"=>1,"foobar"=>2}
  #
  def key_downcase!
    hsh = Hash.new
    self.each do |key,val|
      hsh[key.downcase] = val
    end
    self.replace(hsh)
  end
end

class Hash # :nodoc:
  include ExtendHash
end

