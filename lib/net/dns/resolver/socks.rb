require 'socket'
require 'ipaddr'

class RawSocket # :nodoc:

  @@id_arr = []
  
  def initialize(src_addr,dest_addr)
    
    # Define socket
    begin
      @socket = Socket.new PF_INET, SOCK_RAW, IPPROTO_RAW
    rescue SystemCallError => e
      raise SystemCallError, "You must be root to use raw sockets! #{e}"
    end
    
    @socket.setsockopt IPPROTO_IP, IP_HDRINCL, 1

    # Checks addresses
    @src_addr  = check_addr src_addr
    @dest_addr = check_addr dest_addr

    # Source and destination port are zero
    @src_port  = 0
    @dest_port = 0

    # Set correct protocol version in the header
    @version = @dest_addr.ipv4? ? "0100" : "0110"
    
    # Total lenght: must be overridden by subclasses
    @tot_lenght = 20

    # Protocol: must be overridden by subclasses
    @protocol = 1 # ICMP by default

    # Generate a new id
    # @id = genID
    @id = 1234

    # Generate peer sockaddr
    @to = Socket.pack_sockaddr_in @dest_port, @dest_addr.to_s    
  end

  def send(payload = '')
    packet = make_ip_header([[ @version+'0101', 'B8' ],            # version, hlen
                              [ 0, 'C' ],                          # tos
                              [ @tot_lenght + payload.size, 'n' ], # total len
                              [ @id, 'n' ],                        # id
                              [ 0, 'n' ],                          # flags, offset
                              [ 64, 'C' ],                         # ttl
                              [ @protocol, 'C' ],                  # protocol
                              [ 0, 'n' ],                          # checksum
                              [ @src_addr.to_i, 'N' ],             # source
                              [ @dest_addr.to_i, 'N' ],            # destination
                            ])
    packet << make_transport_header(payload.size)
    packet << [payload].pack("a*")
    @socket.send(packet,0,@to)
  end 

  private
  
  def check_addr addr
    case addr
    when String
      IPAddr.new addr
    when IPAddr
      addr
    else
      raise ArgumentError, "Wrong address format: #{addr}"
    end
  end
  
  def check_port port
    if (1..65535).include? port and port.kind_of? Integer
      port
    else
      raise ArgumentError, "Port #{port} not valid"
    end
  end
  
  def genID
    while (@@id_arr.include?(q = rand(65535)))
    end
    @@id_arr.push(q)
    q
  end

  def ipchecksum(data)
    checksum = data.unpack("n*").inject(0) { |s, x| s + x }
    ((checksum >> 16) + (checksum & 0xffff)) ^ 0xffff
  end

  def make_ip_header(parts)
    template = ''
    data = []
    parts.each do |part|
      data += part[0..-2]
      template << part[-1]
    end
    data_str = data.pack(template)
    checksum = ipchecksum(data_str)
    data[-3] = checksum
    data.pack(template)
  end
  
  def make_transport_header
    ""
  end
  
end

class UdpRawSocket < RawSocket # :nodoc:

  def initialize(src_addr,src_port,dest_addr,dest_port)
    
    super(src_addr,dest_addr)
    
    # Check ports
    @src_port  = check_port src_port
    @dest_port = check_port dest_port
    
    # Total lenght: must be overridden by subclasses
    @tot_lenght = 20 + 8 # 8 bytes => UDP Header

    # Protocol: must be overridden by subclasses
    @protocol = 17 # UDP protocol

    @to = Socket.pack_sockaddr_in @dest_port, @dest_addr.to_s    
  end

  private
  
  def make_udp_header(parts)
    template = ''
    data = []
    parts.each do |part|
      data += part[0..-2]
      template << part[-1]
    end
    data.pack(template)
  end 
  
  def make_transport_header(pay_size)
    make_udp_header([
                      [ @src_port, 'n'],         # source port
                      [ @dest_port, 'n' ],       # destination port
                      [ 8 + pay_size, 'n' ],     # len
                      [ 0, 'n' ]                 # checksum (mandatory)
                    ]) 
  end
  
end

