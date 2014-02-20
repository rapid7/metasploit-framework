# -*- coding: binary -*-
module Msf

###
#
# This module provides methods useful for developing fuzzers
#
###
module Auxiliary::Fuzzer

  #
  # Creates an instance of a fuzzer module
  #
  def initialize(info = {})
    super
    register_advanced_options([
      OptString.new('FuzzTracer',   [ true, 'Sets the magic string to embed into fuzzer string inputs', 'MSFROCKS']),
      OptString.new('FuzzChar',     [ true, 'Sets the character to use for generating long strings', 'X'])
    ], Msf::Auxiliary::Fuzzer)
  end


  #
  # Self-reflective iterators
  #
  def fuzz_numbers
    res = []
    self.methods.sort.grep(/^fuzzer_number/).each do |m|
      @last_fuzzer_input = m
      block_given? ? self.send(m) {|x| yield(x) } : (res << self.send(m))
    end
    res
  end

  def fuzz_strings
    res = []
    self.methods.sort.grep(/^fuzzer_string/).each do |m|
      @last_fuzzer_input = m
      block_given? ? self.send(m) {|x| yield(x) } : (res << self.send(m))
    end
    res
  end

  #
  # General input mangling routines
  #

  # Modify each byte of the string moving forward
  def fuzz_string_corrupt_byte(str,max=nil)
    res = []
    0.upto(max ? [max,str.length-1].min : (str.length - 1)) do |offset|
      0.upto(255) do |val|
        @last_fuzzer_input = "fuzz_string_corrupt_byte offset:#{offset}/#{str.length} byte:#{val}"
        buf = str.dup
        buf[offset,1] = [val].pack('C')
        block_given? ? yield(buf) : (res << buf)
      end
    end
    res
  end

  # Modify each byte of the string moving backward
  def fuzz_string_corrupt_byte_reverse(str,max=nil)
    res = []
    (max ? [max,str.length-1].min : (str.length - 1)).downto(0) do |offset|
      0.upto(255) do |val|
        @last_fuzzer_input = "fuzz_string_corrupt_byte_reverse offset:#{offset}/#{str.length} byte:#{val}"
        buf = str.dup
        buf[offset,1] = [val].pack('C')
        block_given? ? yield(buf) : (res << buf)
      end
    end
    res
  end

  #
  # Useful generators (many derived from AxMan)
  #

  def fuzzer_string_format
    res = %W{ %s %p %n %x %@ %.257d %.65537d %.2147483648d %.257f %.65537f %.2147483648f}
    block_given? ? res.each { |n| yield(n) } : res
  end

  def fuzzer_string_filepath_dos
    res = %W{ aux con nul com1 com2 com3 com4 lpt1 lpt2 lp3 lpt4 prn }
    block_given? ? res.each { |n| yield(n) } : res
  end

  def fuzzer_number_power2
    res = [
      0x100000000,
      0x80000000,
      0x40000000,
      0x20000000,
      0x10000000,
      0x01000000,
      0x00100000,
      0x00010000,
      0x00001000,
      0x00000100,
      0x00000010,
      0x00000001
    ]
    block_given? ? res.each { |n| yield(n) } : res
  end

  def fuzzer_number_power2_plus
    res = []
    fuzzer_number_power2 do |num|
      res << num + 1
      res << num + 2
      res << num - 1
      res << num - 2
      res << num * -1
      res << (num  + 1) * -1
      res << (num  + 2) * -1
    end
    block_given? ? res.each { |n| yield(n) } : res
  end

  def fuzzer_gen_string(len)
    @gen_string_block ||= datastore['FuzzChar'][0,1] * (1024 * 512)
    res = ''
    while (res.length < len)
      res += @gen_string_block
    end
    res[0,len]
  end

  def fuzzer_string_small
    res = []
    16.step(512,16) do |len|
      buf = fuzzer_gen_string(len)
      block_given? ? yield(buf) : (res << buf)
    end
    res
  end

  def fuzzer_string_long
    res = []
    64.step(8192,64) do |len|
      buf = fuzzer_gen_string(len)
      buf[len / 2, datastore['FuzzTracer'].length] = datastore['FuzzTracer']
      block_given? ? yield(buf) : (res << buf)
    end
    res
  end

  def fuzzer_string_giant
    res = []
    512.step(65532 * 2, 512) do |len|
      buf = fuzzer_gen_string(len)
      buf[len / 2, datastore['FuzzTracer'].length] = datastore['FuzzTracer']
      block_given? ? yield(buf) : (res << buf)
    end
    res
  end

  def fuzzer_string_uri_types
    res = %W{
      aaa  aaas  about  acap  adiumxtra  afp  aim  apt  aw  bolo  callto  cap  chrome  cid
      content  crid  cvs  data  dav  designates  dict  disk  dns  doi  ed2k  example  examples
      fax  feed  file  finger  fish  ftp  gg  gizmoproject  go  gopher  h323  hcp  http  https
      iax2  icap  im  imap  info  ipp  irc  ircs  iris  iris.beep  iris.lws  iris.xpc  iris.xpcs
      itms  jar  javascript  keyparc  lastfm  ldap  ldaps  lsid  magnet  mailto  mid  mms  modem
      ms-help  msnim  msrp  msrps  mtqp  mupdate  mvn  news  nfs  nntp  notes  opaquelocktoken
      over  pop  pres  prospero  psyc  res  rlogin  rmi  rsync  rtsp  secondlife  service  sftp
      sgn  shell  shttp  sip  sips  skype  smb  sms  snews  snmp  soap.beep  soap.beeps  soldat
      ssh  steam  svn  tag  teamspeak  tel  telephone  telnet  tftp  thismessage  tip  tv  unreal
      urn  ut2004  vbscript  vemmi  ventrilo  view-source  wais  webcal  worldwind  wtai  wyciwyg
      wysiwyg  xfire  xmlrpc.beep  xmpp  xri  ymsgr  z39.50r  z39.50s
    }
    block_given? ? res.each { |n| yield(n) } : res
  end

  def fuzzer_string_uri_dividers
    res = %W{ : :// }
    block_given? ? res.each { |n| yield(n) } : res
  end

  def fuzzer_string_path_prefixes
    res = %W{ C:\\ \\\\localhost\\ / }
    block_given? ? res.each { |n| yield(n) } : res
  end

  def fuzzer_string_uris_small
    res = []
    fuzzer_string_uri_types do |proto|
      fuzzer_string_uri_dividers do |div|
        fuzzer_string_small do |str|
          buf = proto + div + str
          block_given? ? yield(buf) : (res << buf)
        end
      end
    end
    res
  end

  def fuzzer_string_uris_long
    res = []
    fuzzer_string_uri_types do |proto|
      fuzzer_string_uri_dividers do |div|
        fuzzer_string_long do |str|
          buf = proto + div + str
          block_given? ? yield(buf) : (res << buf)
        end
      end
    end
    res
  end

  def fuzzer_string_uris_giant
    res = []
    fuzzer_string_uri_types do |proto|
      fuzzer_string_uri_dividers do |div|
        fuzzer_string_giant do |str|
          buf = proto + div + str
          block_given? ? yield(buf) : (res << buf)
        end
      end
    end
    res
  end

  def fuzzer_string_uris_format
    res = []
    fuzzer_string_uri_types do |proto|
      fuzzer_string_uri_dividers do |div|
        fuzzer_string_format do |str|
          buf = proto + div + str
          block_given? ? yield(buf) : (res << buf)
        end
      end
    end
    res
  end

  def fuzzer_string_uris_dos
    res = []
    fuzzer_string_uri_types do |proto|
      fuzzer_string_uri_dividers do |div|
        fuzzer_string_filepath_dos do |str|
          buf = proto + div + str
          block_given? ? yield(buf) : (res << buf)
        end
      end
    end
    res
  end

  def fuzzer_string_paths_small
    res = []
    fuzzer_string_path_prefixes do |pre|
      fuzzer_string_small do |str|
        buf = pre + str
        block_given? ? yield(buf) : (res << buf)
      end
    end
    res
  end

  def fuzzer_string_paths_long
    res = []
    fuzzer_string_path_prefixes do |pre|
      fuzzer_string_long do |str|
        buf = pre + str
        block_given? ? yield(buf) : (res << buf)
      end
    end
    res
  end

  def fuzzer_string_paths_giant
    res = []
    fuzzer_string_path_prefixes do |pre|
      fuzzer_string_giant do |str|
        buf = pre + str
        block_given? ? yield(buf) : (res << buf)
      end
    end
    res
  end

  def fuzzer_string_paths_format
    res = []
    fuzzer_string_path_prefixes do |pre|
      fuzzer_string_format do |str|
        buf = pre + str
        block_given? ? yield(buf) : (res << buf)
      end
    end
    res
  end

  def fuzzer_string_paths_dos
    res = []
    fuzzer_string_path_prefixes do |pre|
      fuzzer_string_filepath_dos do |str|
        buf = pre + str
        block_given? ? yield(buf) : (res << buf)
      end
    end
    res
  end

end
end
