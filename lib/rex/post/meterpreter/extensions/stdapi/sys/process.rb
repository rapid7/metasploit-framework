# -*- coding: binary -*-

require 'rex/post/process'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/channels/pools/stream_pool'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

require 'rex/post/meterpreter/extensions/stdapi/sys/process_subsystem/image'
require 'rex/post/meterpreter/extensions/stdapi/sys/process_subsystem/io'
require 'rex/post/meterpreter/extensions/stdapi/sys/process_subsystem/memory'
require 'rex/post/meterpreter/extensions/stdapi/sys/process_subsystem/thread'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

##
#
# This class implements the Rex::Post::Process interface.
#
##
class Process < Rex::Post::Process

  include Rex::Post::Meterpreter::ObjectAliasesContainer

  ##
  #
  # Class methods
  #
  ##

  class << self
    attr_accessor :client
  end

  #
  # Returns the process identifier of the process supplied in key if it's
  # valid.
  #
  def Process.[](key)
    return if key.nil?

    each_process { |p|
      if (p['name'].downcase == key.downcase)
        return p['pid']
      end
    }

    return nil
  end

  #
  # Attaches to the supplied process with a given set of permissions.
  #
  def Process.open(pid = nil, perms = nil)
    real_perms = 0

    if (perms == nil)
      perms = PROCESS_ALL
    end

    if (perms & PROCESS_READ) > 0
      real_perms |= PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    end

    if (perms & PROCESS_WRITE) > 0
      real_perms |= PROCESS_SET_SESSIONID | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION
    end

    if (perms & PROCESS_EXECUTE) > 0
      real_perms |= PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS | PROCESS_SUSPEND_RESUME
    end

    return _open(pid, real_perms)
  end

  #
  # Low-level process open.
  #
  def Process._open(pid, perms, inherit = false)
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_ATTACH)

    if (pid == nil)
      pid = 0
    end

    # Populate the request
    request.add_tlv(TLV_TYPE_PID, pid)
    request.add_tlv(TLV_TYPE_PROCESS_PERMS, perms)
    request.add_tlv(TLV_TYPE_INHERIT, inherit)

    # Transmit the request
    response = self.client.send_request(request)
    handle   = response.get_tlv_value(TLV_TYPE_HANDLE)

    # If the handle is valid, allocate a process instance and return it
    if (handle != nil)
      return self.new(pid, handle)
    end

    return nil
  end

  #
  # Executes an application using the arguments provided
  # @param path [String] Path on the remote system to the executable to run
  # @param arguments [String,Array<String>] Arguments to the process. When passed as a String (rather than an array of Strings),
  #                                         this is treated as a string containing all arguments.
  # @param opts [Hash] Optional settings to parameterise the process launch
  # @option Hidden [Boolean] Is the process launched without creating a visible window
  # @option Channelized [Boolean] The process is launched with pipes connected to a channel, e.g. for sending input/receiving output
  # @option Suspended [Boolean] Start the process suspended
  # @option UseThreadToken [Boolean] Use the thread token (as opposed to the process token) to launch the process
  # @option Desktop [Boolean] Run on meterpreter's current desktopt
  # @option Session [Integer] Execute process in a given session as the session user
  # @option Subshell [Boolean] Execute process in a subshell
  # @option Pty [Boolean] Execute process in a pty (if available)
  # @option ParentId [Integer] Spoof the parent PID (if possible)
  # @option InMemory [Boolean,String] Execute from memory (`path` is treated as a local file to upload, and the actual path passed
  #                                   to meterpreter is this parameter's value, if provided as a String)
  # @option :legacy_args [String] When arguments is an array, this is the command to execute if the receiving Meterpreter does not support arguments as an array
  #
  def Process.execute(path, arguments = '', opts = nil)
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_EXECUTE)
    flags   = 0

    # If we were supplied optional arguments...
    if (opts != nil)
      if (opts['Hidden'])
        flags |= PROCESS_EXECUTE_FLAG_HIDDEN
      end
      if (opts['Channelized'])
        flags |= PROCESS_EXECUTE_FLAG_CHANNELIZED
      end
      if (opts['Suspended'])
        flags |= PROCESS_EXECUTE_FLAG_SUSPENDED
      end
      if (opts['UseThreadToken'])
        flags |= PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN
      end
      if (opts['Desktop'])
        flags |= PROCESS_EXECUTE_FLAG_DESKTOP
      end
      if (opts['Session'])
        flags |= PROCESS_EXECUTE_FLAG_SESSION
        request.add_tlv( TLV_TYPE_PROCESS_SESSION, opts['Session'] )
      end
      if (opts['Subshell'])
        flags |= PROCESS_EXECUTE_FLAG_SUBSHELL
      end
      if (opts['Pty'])
        flags |= PROCESS_EXECUTE_FLAG_PTY
      end
      if (opts['ParentPid'])
        request.add_tlv(TLV_TYPE_PARENT_PID, opts['ParentPid']);
        request.add_tlv(TLV_TYPE_PROCESS_PERMS, PROCESS_ALL_ACCESS)
        request.add_tlv(TLV_TYPE_INHERIT, false)
      end
      inmem = opts['InMemory']
      if inmem

        # add the file contents into the tlv
        f = ::File.new(path, 'rb')
        request.add_tlv(TLV_TYPE_VALUE_DATA, f.read(f.stat.size))
        f.close

        # replace the path with the "dummy"
        path = inmem.kind_of?(String) ? inmem : 'cmd'
      end
    end

    # Add arguments
    # If process arguments were supplied
    if arguments.kind_of?(Array)
      request.add_tlv(TLV_TYPE_PROCESS_UNESCAPED_PATH, client.unicode_filter_decode( path ))
      # This flag is needed to disambiguate how to handle escaping special characters in the path when no arguments are provided
      flags |= PROCESS_EXECUTE_FLAG_ARG_ARRAY
      arguments.each do |arg|
        request.add_tlv(TLV_TYPE_PROCESS_ARGUMENT, arg);
      end
      if opts[:legacy_path]
        request.add_tlv(TLV_TYPE_PROCESS_PATH, opts[:legacy_path])
      end
      if opts[:legacy_args]
        request.add_tlv(TLV_TYPE_PROCESS_ARGUMENTS, opts[:legacy_args])
      end
    elsif arguments.nil? || arguments.kind_of?(String)
      request.add_tlv(TLV_TYPE_PROCESS_PATH, client.unicode_filter_decode( path ))
      request.add_tlv(TLV_TYPE_PROCESS_ARGUMENTS, arguments)
    else
      raise ArgumentError.new('Unknown type for arguments')
    end

    request.add_tlv(TLV_TYPE_PROCESS_FLAGS, flags);

    response = client.send_request(request)

    # Get the response parameters
    pid        = response.get_tlv_value(TLV_TYPE_PID)
    handle     = response.get_tlv_value(TLV_TYPE_PROCESS_HANDLE)
    channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)
    channel    = nil

    # If we were creating a channel out of this
    if (channel_id != nil)
      channel = Rex::Post::Meterpreter::Channels::Pools::StreamPool.new(client,
          channel_id, "stdapi_process", CHANNEL_FLAG_SYNCHRONOUS, response)
    end

    # Return a process instance
    return self.new(pid, handle, channel)
  end

  #
  # Execute an application and capture the output
  #
  def Process.capture_output(path, arguments = '', opts = nil, time_out = 15)
    start = Time.now.to_i
    process = execute(path, arguments, opts)
    data = ""

    # Wait up to time_out seconds for the first bytes to arrive
    while (d = process.channel.read)
      data << d
      if d == ""
        if Time.now.to_i - start < time_out
          sleep 0.1
        else
          break
        end
      end
    end
    data.chomp! if data

    begin
      process.channel.close
    rescue IOError => e
      # Channel was already closed, but we got the cmd output, so let's soldier on.
    end
    process.close

    return data
  end

  #
  # Kills one or more processes.
  #
  def Process.kill(*args)
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_KILL)

    args.each { |id|
      request.add_tlv(TLV_TYPE_PID, id)
    }

    client.send_request(request)

    return true
  end

  #
  # Gets the process id that the remote side is executing under.
  #
  def Process.getpid
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_GETPID)

    response = client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_PID)
  end

  #
  # Enumerates all of the elements in the array returned by get_processes.
  #
  def Process.each_process(&block)
    self.get_processes.each(&block)
  end

  #
  # Returns a ProcessList of processes as Hash objects with keys for 'pid',
  # 'ppid', 'name', 'path', 'user', 'session' and 'arch'.
  #
  def Process.get_processes
    request   = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_GET_PROCESSES)
    processes = ProcessList.new

    response = client.send_request(request)

    response.each(TLV_TYPE_PROCESS_GROUP) { |p|
    arch = ""

    pa = p.get_tlv_value(TLV_TYPE_PROCESS_ARCH)
    if !pa.nil?
      if pa == 1 # PROCESS_ARCH_X86
        arch = ARCH_X86
      elsif pa == 2 # PROCESS_ARCH_X64
        arch = ARCH_X64
      end
    else
      arch = p.get_tlv_value(TLV_TYPE_PROCESS_ARCH_NAME)
    end

    processes <<
        {
          'pid'      => p.get_tlv_value(TLV_TYPE_PID),
          'ppid'     => p.get_tlv_value(TLV_TYPE_PARENT_PID),
          'name'     => client.unicode_filter_encode( p.get_tlv_value(TLV_TYPE_PROCESS_NAME) ),
          'path'     => client.unicode_filter_encode( p.get_tlv_value(TLV_TYPE_PROCESS_PATH) ),
          'session'  => p.get_tlv_value(TLV_TYPE_PROCESS_SESSION),
          'user'     => client.unicode_filter_encode( p.get_tlv_value(TLV_TYPE_USER_NAME) ),
          'arch'     => arch
        }
    }

    return processes
  end

  #
  # An alias for get_processes.
  #
  def Process.processes
    self.get_processes
  end

  #
  # Search memory for supplied regexes and return matches
  #
  def Process.memory_search(pid: 0, needles: [''], min_match_length: 5, max_match_length: 127)
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_SEARCH)

    request.add_tlv(TLV_TYPE_PID, pid)
    needles.each { |needle| request.add_tlv(TLV_TYPE_MEMORY_SEARCH_NEEDLE, needle) }
    request.add_tlv(TLV_TYPE_MEMORY_SEARCH_MATCH_LEN, max_match_length)
    request.add_tlv(TLV_TYPE_UINT, min_match_length)

    self.client.send_request(request)
  end

  ##
  #
  # Instance methods
  #
  ##

  #
  # Initializes the process instance and its aliases.
  #
  def initialize(pid, handle, channel = nil)
    self.client  = self.class.client
    self.handle  = handle
    self.channel = channel

    # If the process identifier is zero, then we must lookup the current
    # process identifier
    if (pid == 0)
      self.pid = client.sys.process.getpid
    else
      self.pid = pid
    end

    initialize_aliases(
      {
        'image'  => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Image.new(self),
        'io'     => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::IO.new(self),
        'memory' => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Memory.new(self),
        'thread' => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Thread.new(self),
      })

    # Ensure the remote object is closed when all references are removed
    ObjectSpace.define_finalizer(self, self.class.finalize(client, handle))
  end

  def self.finalize(client, handle)
    proc do
      deferred_close_proc = proc do
        begin
          self.close(client, handle)
        rescue => e
          elog("finalize method for Process failed", error: e)
        end
      end

      # Schedule the finalizing logic out-of-band; as this logic might be called in the context of a Signal.trap, which can't synchronize mutexes
      client.framework.sessions.schedule(deferred_close_proc)
    end
  end

  #
  # Returns the executable name of the process.
  #
  def name
    return get_info()['name']
  end

  #
  # Returns the path to the process' executable.
  #
  def path
    return get_info()['path']
  end

  #
  # Closes the handle to the process that was opened.
  #
  def self.close(client, handle)
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_CLOSE)
    request.add_tlv(TLV_TYPE_HANDLE, handle)
    client.send_request(request, nil)
    handle = nil
    return true
  end

  #
  # Instance method
  #
  def close(handle = self.handle)
    unless self.pid.nil?
      ObjectSpace.undefine_finalizer(self)
      self.class.close(self.client, handle)
      self.pid = nil
    end
  end

  #
  # Block until this process terminates on the remote side.
  # By default we choose not to allow a packet response timeout to
  # occur as we may be waiting indefinatly for the process to terminate.
  #
  def wait( timeout = -1 )
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_WAIT)

    request.add_tlv(TLV_TYPE_HANDLE, self.handle)

    self.client.send_request(request, timeout)

    self.handle = nil

    return true
  end

  attr_reader   :client, :handle, :channel, :pid # :nodoc:
protected
  attr_writer   :client, :handle, :channel, :pid # :nodoc:

  #
  # Gathers information about the process and returns a hash.
  #
  def get_info
    request = Packet.create_request(COMMAND_ID_STDAPI_SYS_PROCESS_GET_INFO)
    info    = {}

    request.add_tlv(TLV_TYPE_HANDLE, handle)

    # Send the request
    response = client.send_request(request)

    # Populate the hash
    info['name'] = client.unicode_filter_encode( response.get_tlv_value(TLV_TYPE_PROCESS_NAME) )
    info['path'] = client.unicode_filter_encode( response.get_tlv_value(TLV_TYPE_PROCESS_PATH) )

    return info
  end

end

#
# Simple wrapper class for storing processes
#
class ProcessList < Array

  #
  # Create a Rex::Text::Table out of the processes stored in this list
  #
  # +opts+ is passed on to Rex::Text::Table.new, mostly unmolested
  #
  # Note that this output is affected by Rex::Post::Meterpreter::Client#unicode_filter_encode
  #
  def to_table(opts={})
    if empty?
      return Rex::Text::Table.new(opts)
    end

    column_headers = [ "PID", "PPID", "Name", "Arch", "Session", "User", "Path" ]
    column_headers.delete_if do |h|
      none? { |process| process.has_key?(h.downcase) } ||
      all? { |process| process[h.downcase].nil? }
    end

    opts = {
      'Header' => 'Process List',
      'Indent' => 1,
      'Columns' => column_headers
    }.merge(opts)

    tbl = Rex::Text::Table.new(opts)
    each do |process|
      tbl << column_headers.map do |header|
        col = header.downcase
        next unless process.keys.any? { |process_header| process_header == col }
        val = process[col]
        if col == 'session'
          val == 0xFFFFFFFF ? '' : val.to_s
        else
          val
        end
      end
    end

    tbl
  end
end

end; end; end; end; end; end
