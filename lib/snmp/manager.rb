#
# Copyright (c) 2004 David R. Halliday
# All rights reserved.
#
# This SNMP library is free software.  Redistribution is permitted under the
# same terms and conditions as the standard Ruby distribution.  See the
# COPYING file in the Ruby distribution for details.
#

require 'snmp/pdu'
require 'snmp/mib'
require 'socket'
require 'timeout'
require 'thread'

module SNMP

class RequestTimeout < RuntimeError; end

##
# Wrap socket so that it can be easily substituted for testing or for
# using other transport types (e.g. TCP)
#
class UDPTransport
    def initialize(socket = nil)
        @socket = socket

        if socket.nil?
            @socket = UDPSocket.open
        end
    end

    def close
        @socket.close
    end

    def send(data, host, port)
        @socket.send(data, 0, host, port)
    end

    def recv(max_bytes)
        @socket.recv(max_bytes)
    end
end


class RexUDPTransport
    def initialize(socket = nil)
        @socket = socket

        if socket.nil?
            @socket = UDPSocket.open
        end
    end

    def close
        @socket.close
    end

    def send(data, host, port, flags = 0)
        begin
            @socket.sendto(data, host, port, flags)
        rescue NoMethodError
            @socket.send(data, 0, host, port)
        end

    end

    def recv(max_bytes)
        @socket.recv(max_bytes)
    end
end


##
# Manage a request-id in the range 1..2**31-1
#
class RequestId
    MAX_REQUEST_ID = 2**31
    
    def initialize
        @lock = Mutex.new
        @request_id = rand(MAX_REQUEST_ID)
    end

    def next
        @lock.synchronize do
            @request_id += 1
            @request_id = 1 if @request_id == MAX_REQUEST_ID
            return  @request_id
        end
    end
    
    def force_next(next_id)
        new_request_id = next_id.to_i
        if new_request_id < 1 || new_request_id >= MAX_REQUEST_ID
            raise "Invalid request id: #{new_request_id}"
        end
        new_request_id = MAX_REQUEST_ID if new_request_id == 1
        @lock.synchronize do
            @request_id = new_request_id - 1
        end
    end
end
    
##
# == SNMP Manager
#
# This class provides a manager for interacting with a single SNMP agent.
#
# = Example
#
#    require 'snmp'
#
#    manager = SNMP::Manager.new(:Host => 'localhost', :Port => 1061)
#    response = manager.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0"])
#    response.each_varbind {|vb| puts vb.inspect}
#    manager.close
#
# == Symbolic Object Names
# 
# Symbolic names for SNMP object IDs can be used as parameters to the
# APIs in this class if the MIB modules are imported and the names of the
# MIBs are included in the MibModules configuration parameter.
#
# See MIB.varbind_list for a description of valid parameter formats.
#
# The following modules are loaded by default: "SNMPv2-SMI", "SNMPv2-MIB",
# "IF-MIB", "IP-MIB", "TCP-MIB", "UDP-MIB".  All of the current IETF MIBs
# have been imported and are available for loading.
#
# Additional modules may be imported using the MIB class.  The
# current implementation of the importing code requires that the
# external 'smidump' tool is available in your PATH. This tool can be 
# obtained from the libsmi website at
# http://www.ibr.cs.tu-bs.de/projects/libsmi/ .
#
# = Example
#
# Do this once:
#
#   SNMP::MIB.import_module(MY_MODULE_FILENAME, MIB_OUTPUT_DIR)
#
# Include your module in MibModules each time you create a Manager:
#
#   SNMP::Manager.new(:Host => 'localhost', :MibDir => MIB_OUTPUT_DIR,
#                     :MibModules => ["MY-MODULE-MIB", "SNMPv2-MIB", ...])
#

class Manager

    ##
    # Default configuration.  Individual options may be overridden when
    # the Manager is created.
    #
    DefaultConfig = {
        :Host => 'localhost',
        :Port => 161,
        :TrapPort => 162,
        :Socket => nil,
        :Community => 'public',
        :WriteCommunity => nil,
        :Version => :SNMPv2c,
        :Timeout => 1,
        :Retries => 5,
        :Transport => UDPTransport,
        :MaxReceiveBytes => 8000,
        :MibDir => MIB::DEFAULT_MIB_PATH,
        :MibModules => ["SNMPv2-SMI", "SNMPv2-MIB", "IF-MIB", "IP-MIB", "TCP-MIB", "UDP-MIB"]}

    @@request_id = RequestId.new
    
    ##
    # Retrieves the current configuration of this Manager.
    #
    attr_reader :config
    
    ##
    # Retrieves the MIB for this Manager.
    #
    attr_reader :mib
    
    def initialize(config = {})
        if block_given?
            warn "SNMP::Manager::new() does not take block; use SNMP::Manager::open() instead"
        end
        @config = DefaultConfig.merge(config)
        @config[:WriteCommunity] = @config[:WriteCommunity] || @config[:Community]
        @host = @config[:Host]
        @port = @config[:Port]
        @socket = @config[:Socket]
        @trap_port = @config[:TrapPort]
        @community = @config[:Community]
        @write_community = @config[:WriteCommunity]
        @snmp_version = @config[:Version]
        @timeout = @config[:Timeout]
        @retries = @config[:Retries]
        @transport = @config[:Transport].new(@socket)
        @max_bytes = @config[:MaxReceiveBytes]
        @mib = MIB.new
        load_modules(@config[:MibModules], @config[:MibDir])
    end
    
    ##
    # Creates a Manager but also takes an optional block and automatically
    # closes the transport connection used by this manager after the block
    # completes.
    #
    def self.open(config = {})
        manager = Manager.new(config)
        if block_given?
            begin
                yield manager
            ensure
                manager.close
            end
        end
    end
    
    ##
    # Close the transport connection for this manager.
    #
    def close
        @transport.close
    end
            
    def load_module(name)
        @mib.load_module(name)
    end
    
    ##
    # Sends a get request for the supplied list of ObjectId or VarBind
    # objects.
    #
    # Returns a Response PDU with the results of the request.
    #
    def get(object_list)
        varbind_list = @mib.varbind_list(object_list, :NullValue)
        request = GetRequest.new(@@request_id.next, varbind_list)
        try_request(request)
    end

    ##
    # Sends a get request for the supplied list of ObjectId or VarBind
    # objects.
    #
    # Returns a list of the varbind values only, not the entire response,
    # in the same order as the initial object_list.  This method is
    # useful for retrieving scalar values.
    #
    # For example:
    #
    #   SNMP::Manager.open(:Host => "localhost") do |manager|
    #     puts manager.get_value("sysDescr.0")
    #   end
    #
    def get_value(object_list)
        if object_list.respond_to? :to_ary
            get(object_list).vb_list.collect { |vb| vb.value }
        else
            get(object_list).vb_list.first.value
        end
    end
    
    ##
    # Sends a get-next request for the supplied list of ObjectId or VarBind
    # objects.
    #
    # Returns a Response PDU with the results of the request.
    #
    def get_next(object_list)
        varbind_list = @mib.varbind_list(object_list, :NullValue)
        request = GetNextRequest.new(@@request_id.next, varbind_list)
        try_request(request)
    end
    
    ##
    # Sends a get-bulk request.  The non_repeaters parameter specifies
    # the number of objects in the object_list to be retrieved once.  The
    # remaining objects in the list will be retrieved up to the number of
    # times specified by max_repetitions.
    #
    def get_bulk(non_repeaters, max_repetitions, object_list)
        varbind_list = @mib.varbind_list(object_list, :NullValue)
        request = GetBulkRequest.new(
                @@request_id.next,
                varbind_list,
                non_repeaters,
                max_repetitions)
        try_request(request)
    end
    
    ##
    # Sends a set request using the supplied list of VarBind objects.
    #
    # Returns a Response PDU with the results of the request.
    #
    def set(object_list)
        varbind_list = @mib.varbind_list(object_list, :KeepValue)
        request = SetRequest.new(@@request_id.next, varbind_list)
        try_request(request, @write_community)
    end

    ##
    # Sends an SNMPv1 style trap.
    #
    # enterprise: The enterprise OID from the IANA assigned numbers
    # (http://www.iana.org/assignments/enterprise-numbers) as a String or
    # an ObjectId.
    #
    # agent_addr: The IP address of the SNMP agent as a String or IpAddress.
    #
    # generic_trap: The generic trap identifier.  One of :coldStart,
    # :warmStart, :linkDown, :linkUp, :authenticationFailure,
    # :egpNeighborLoss, or :enterpriseSpecific 
    #
    # specific_trap: An integer representing the specific trap type for
    # an enterprise-specific trap.
    #
    # timestamp: An integer respresenting the number of hundredths of
    # a second that this system has been up.
    #
    # object_list: A list of additional varbinds to send with the trap. 
    #
    # For example:
    #
    #   Manager.open(:Version => :SNMPv1) do |snmp|
    #     snmp.trap_v1(
    #       "enterprises.9",
    #       "10.1.2.3",
    #       :enterpriseSpecific,
    #        42,
    #       12345,
    #       [VarBind.new("1.3.6.1.2.3.4", Integer.new(1))])
    #  end
    #
    def trap_v1(enterprise, agent_addr, generic_trap, specific_trap, timestamp, object_list=[])
        vb_list = @mib.varbind_list(object_list, :KeepValue)
        ent_oid = @mib.oid(enterprise)
        agent_ip = IpAddress.new(agent_addr)
        specific_int = Integer(specific_trap)
        ticks = TimeTicks.new(timestamp)
        trap = SNMPv1_Trap.new(ent_oid, agent_ip, generic_trap, specific_int, ticks, vb_list)
        send_request(trap, @community, @host, @trap_port)
    end
    
    ##
    # Sends an SNMPv2c style trap.
    #
    # sys_up_time: An integer respresenting the number of hundredths of
    # a second that this system has been up.
    #
    # trap_oid: An ObjectId or String with the OID identifier for this
    # trap.
    #
    # object_list: A list of additional varbinds to send with the trap. 
    #
    def trap_v2(sys_up_time, trap_oid, object_list=[])
        vb_list = create_trap_vb_list(sys_up_time, trap_oid, object_list)
        trap = SNMPv2_Trap.new(@@request_id.next, vb_list)
        send_request(trap, @community, @host, @trap_port)
    end
                
    ##
    # Sends an inform request using the supplied varbind list. 
    #
    # sys_up_time: An integer respresenting the number of hundredths of
    # a second that this system has been up.
    #
    # trap_oid: An ObjectId or String with the OID identifier for this
    # inform request.
    #
    # object_list: A list of additional varbinds to send with the inform. 
    #
    def inform(sys_up_time, trap_oid, object_list=[])
        vb_list = create_trap_vb_list(sys_up_time, trap_oid, object_list)
        request = InformRequest.new(@@request_id.next, vb_list)
        try_request(request, @community, @host, @trap_port)
    end
    
    ##
    # Helper method for building VarBindList for trap and inform requests.
    #
    def create_trap_vb_list(sys_up_time, trap_oid, object_list)
        vb_args = @mib.varbind_list(object_list, :KeepValue)
        uptime_vb = VarBind.new(SNMP::SYS_UP_TIME_OID, TimeTicks.new(sys_up_time.to_int))
        trap_vb = VarBind.new(SNMP::SNMP_TRAP_OID_OID, @mib.oid(trap_oid))
        VarBindList.new([uptime_vb, trap_vb, *vb_args])
    end
    
    ##
    # Walks a list of ObjectId or VarBind objects using get_next until
    # the response to the first OID in the list reaches the end of its
    # MIB subtree.
    #
    # The varbinds from each get_next are yielded to the given block as
    # they are retrieved.  The result is yielded as a VarBind when walking
    # a single object or as a VarBindList when walking a list of objects.
    #
    # Normally this method is used for walking tables by providing an
    # ObjectId for each column of the table.
    #
    # For example:
    #
    #   SNMP::Manager.open(:Host => "localhost") do |manager|
    #     manager.walk("ifTable") { |vb| puts vb }
    #   end
    #
    #   SNMP::Manager.open(:Host => "localhost") do |manager|
    #     manager.walk(["ifIndex", "ifDescr"]) do |index, descr| 
    #       puts "#{index.value} #{descr.value}"
    #     end
    #   end
    #
    # The index_column identifies the column that will provide the index
    # for each row.  This information is used to deal with "holes" in a
    # table (when a row is missing a varbind for one column).  A missing
    # varbind is replaced with a varbind with the value NoSuchInstance.
    #
    # Note: If you are getting back rows where all columns have a value of
    # NoSuchInstance then your index column is probably missing one of the
    # rows.  Choose an index column that includes all indexes for the table.
    # 
    def walk(object_list, index_column=0)
        raise ArgumentError, "expected a block to be given" unless block_given?
        vb_list = @mib.varbind_list(object_list, :NullValue)
        raise ArgumentError, "index_column is past end of varbind list" if index_column >= vb_list.length
        is_single_vb = object_list.respond_to?(:to_str) ||
                       object_list.respond_to?(:to_varbind)
        start_list = vb_list
        start_oid = vb_list[index_column].name
        last_oid = start_oid
        loop do
            vb_list = get_next(vb_list).vb_list
            index_vb = vb_list[index_column]
            break if EndOfMibView == index_vb.value 
            stop_oid = index_vb.name
            if stop_oid <= last_oid
                warn "OIDs are not increasing, #{last_oid} followed by #{stop_oid}"
                break
            end
            break unless stop_oid.subtree_of?(start_oid)
            last_oid = stop_oid
            if is_single_vb
                yield index_vb
            else
                vb_list = validate_row(vb_list, start_list, index_column)
                yield vb_list
            end
        end
    end
    
    ##
    # Helper method for walk.  Checks all of the VarBinds in vb_list to
    # make sure that the row indices match.  If the row index does not
    # match the index column, then that varbind is replaced with a varbind
    # with a value of NoSuchInstance.
    #
    def validate_row(vb_list, start_list, index_column)
        start_vb = start_list[index_column]
        index_vb = vb_list[index_column]
        row_index = index_vb.name.index(start_vb.name)
        vb_list.each_index do |i|
            if i != index_column
                expected_oid = start_list[i].name + row_index 
                if vb_list[i].name != expected_oid
                    vb_list[i] = VarBind.new(expected_oid, NoSuchInstance)
                end
            end
        end
        vb_list
    end
    private :validate_row
    
    ##
    # Set the next request-id instead of letting it be generated
    # automatically. This method is useful for testing and debugging.
    #
    def next_request_id=(request_id)
        @@request_id.force_next(request_id)
    end
    
    private

    def warn(message)
        trace = caller(2)
        location = trace[0].sub(/:in.*/,'')
        Kernel::warn "#{location}: warning: #{message}"
    end
    
    def load_modules(module_list, mib_dir)
        module_list.each { |m| @mib.load_module(m, mib_dir) }
    end
    
    def try_request(request, community=@community, host=@host, port=@port)
        (@retries.to_i + 1).times do |n|
            send_request(request, community, host, port)
            begin
                timeout(@timeout) do
                    return get_response(request)
                end
            rescue Timeout::Error
                # no action - try again
            end
        end
        raise RequestTimeout, "host #{@config[:Host]} not responding", caller
    end
    
    def send_request(request, community, host, port)
        message = Message.new(@snmp_version, community, request)
        @transport.send(message.encode, host, port)
    end
    
    ##
    # Wait until response arrives.  Ignore responses with mismatched IDs;
    # these responses are typically from previous requests that timed out
    # or almost timed out.
    #
    def get_response(request)
        begin
            data = @transport.recv(@max_bytes)
            message = Message.decode(data)
            response = message.pdu
        end until request.request_id == response.request_id
        response
    end
end

class UDPServerTransport
    def initialize(host, port)
        @socket = UDPSocket.open
        @socket.bind(host, port)
    end
    
    def close
        @socket.close
    end

    def send(data, host, port)
        @socket.send(data, 0, host, port)
    end
    
    def recvfrom(max_bytes)
        data, host_info = @socket.recvfrom(max_bytes)
        flags, host_port, host_name, host_ip = host_info
        return data, host_ip, host_port
    end
end

##
# == SNMP Trap Listener
#
# Listens to a socket and processes received traps and informs in a separate
# thread.
#
# === Example
#
#   require 'snmp'
#
#   m = SNMP::TrapListener.new(:Port => 1062, :Community => 'public') do |manager|
#     manager.on_trap_default { |trap| p trap }
#   end
#   m.join
#
class TrapListener
    DefaultConfig = {
        :Host => 'localhost',
        :Port => 162,
        :Community => 'public',
        :ServerTransport => UDPServerTransport,
        :MaxReceiveBytes => 8000}

    NULL_HANDLER = Proc.new {}
    
    ##
    # Start a trap handler thread.  If a block is provided then the block
    # is executed before trap handling begins.  This block is typically used
    # to define the trap handler blocks.
    #
    # The trap handler blocks execute in the context of the trap handler thread.
    #
    # The most specific trap handler is executed when a trap arrives.  Only one
    # handler is executed.  The handlers are checked in the following order:
    #
    # 1. handler for a specific OID
    # 2. handler for a specific SNMP version
    # 3. default handler
    #
    def initialize(config={}, &block)
        @config = DefaultConfig.dup.update(config)
        @transport = @config[:ServerTransport].new(@config[:Host], @config[:Port])
        @max_bytes = @config[:MaxReceiveBytes]
        @handler_init = block
        @oid_handler = {}
        @v1_handler = nil
        @v2c_handler = nil
        @default_handler = nil
        @lock = Mutex.new
        @handler_thread = Thread.new(self) { |m| process_traps(m) }
    end
    
    ##
    # Define the default trap handler.  The default trap handler block is
    # executed only if no other block is applicable.  This handler should
    # expect to receive both SNMPv1_Trap and SNMPv2_Trap objects.
    #
    def on_trap_default(&block)
        raise ArgumentError, "a block must be provided" unless block
        @lock.synchronize { @default_handler = block }
    end
    
    ##
    # Define a trap handler block for a specific trap ObjectId.  This handler
    # only applies to SNMPv2 traps.  Note that symbolic OIDs are not
    # supported by this method (like in the SNMP.Manager class).
    #
    def on_trap(object_id, &block)
        raise ArgumentError, "a block must be provided" unless block
        @lock.synchronize { @oid_handler[ObjectId.new(object_id)] = block }
    end

    ##
    # Define a trap handler block for all SNMPv1 traps.  The trap yielded
    # to the block will always be an SNMPv1_Trap.
    #
    def on_trap_v1(&block)
        raise ArgumentError, "a block must be provided" unless block
        @lock.synchronize { @v1_handler = block }
    end
    
    ##
    # Define a trap handler block for all SNMPv2c traps.  The trap yielded
    # to the block will always be an SNMPv2_Trap.  Note that InformRequest
    # is a subclass of SNMPv2_Trap, so inform PDUs are also received by
    # this handler.
    #
    def on_trap_v2c(&block)
        raise ArgumentError, "a block must be provided" unless block
        @lock.synchronize { @v2c_handler = block }
    end
    
    ##
    # Joins the current thread to the trap handler thread.
    #
    # See also Thread#join.
    #
    def join
        @handler_thread.join
    end
    
    ##
    # Stops the trap handler thread and releases the socket.
    #
    # See also Thread#exit.
    #
    def exit
        @handler_thread.exit
        @transport.close
    end
    
    alias kill exit
    alias terminate exit
    
    private
    
    def process_traps(trap_listener)
        @handler_init.call(trap_listener) if @handler_init
        loop do
            data, source_ip, source_port = @transport.recvfrom(@max_bytes)
            begin
                message = Message.decode(data)
                if @config[:Community] == message.community
                    trap = message.pdu
                    if trap.kind_of?(InformRequest)
                        @transport.send(message.response.encode, source_ip, source_port)
                    end
                    trap.source_ip = source_ip
                    select_handler(trap).call(trap)
                end
            rescue => e
                puts "Error handling trap: #{e}"
                puts e.backtrace.join("\n")
                puts "Received data:"
                p data  
            end
        end
    end
    
    def select_handler(trap)
        @lock.synchronize do
            if trap.kind_of?(SNMPv2_Trap)
                oid = trap.trap_oid
                if @oid_handler[oid]
                    return @oid_handler[oid]
                elsif @v2c_handler
                    return @v2c_handler
                elsif @default_handler
                    return @default_handler
                else
                    return NULL_HANDLER
                end
            elsif trap.kind_of?(SNMPv1_Trap)
                if @v1_handler
                    return @v1_handler
                elsif @default_handler
                    return @default_handler
                else
                    return NULL_HANDLER
                end
            else
                return NULL_HANDLER
            end
        end
    end
end

end
