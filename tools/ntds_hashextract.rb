#!/usr/bin/env ruby
# This is a tool that can be used to extract AD password hashes from NTDS.dit
# It is required that you first export the 'datatable' from NTDS.dit using forensic
# tools such as 'libesedb' and 'NTDSXtract'
#

msfbase = __FILE__
while File.symlink?(msfbase)
        msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'rex/registry/hive'
require 'msf/core'

unless ARGV.length > 0
  puts "USAGE: ./ntds_hashextract.rb <datatable> <SYSTEM HIVE>\r\n\r\n"
  exit!
end    

@db = File.open(ARGV[0], 'rb')
@line = @db.readline.to_s
@record = @line.split("\t")
@nthash = @record.index("ATTk589914")
@lmhash = @record.index("ATTk589879")
@username = @record.index("ATTm590045")
@pek = @record.index("ATTk590689")
@sid = @record.index("ATTr589970")
@sys = Rex::Registry::Hive.new(ARGV[1])
@parity = [
  1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
  16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
  32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
  49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
  64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
  81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
  97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
  112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
  128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
  145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
  161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
  176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
  193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
  208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
   24,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
  241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
]


def get_pek(db)
	db.each_line do |line|
		record = line.to_s.split("\t")
		pek = record[@pek]
		if !pek.to_s.empty?
			return [pek[16,pek.size].to_s].pack("H*")
		end
	end
	return "No Pek"
end

def get_boot_key(hive)
  return if !hive.root_key
  return if !hive.root_key.name
  default_control_set = hive.value_query('\Select\Default').value.data.unpack("c").first
  bootkey = ""
  basekey = "\\ControlSet00#{default_control_set}\\Control\\Lsa"
  %W{JD Skew1 GBG Data}.each do |k|
    ok = hive.relative_query(basekey + "\\" + k)
    return nil if not ok
    tmp = ""
    0.upto(ok.class_name_length - 1) do |i|
      next if i%2 == 1
      tmp << ok.class_name_data[i,1]
    end
    bootkey << [tmp].pack("H*")
  end
  keybytes = bootkey.unpack("C*")              
  p = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
  scrambled = ""
  p.each do |i|
    scrambled << bootkey[i]
  end
  return scrambled
end

def decrypt_pek(bootkey, enc_pek)
  md5 = Digest::MD5.new
  md5.update(bootkey)
  for i in (0...1000)
    md5.update(enc_pek[0,16])
  end
  rc4 = OpenSSL::Cipher::Cipher.new('rc4')
  rc4.key = md5.digest
  pek=rc4.update(enc_pek[16,enc_pek.size])
  return pek[36,pek.size]
end

def decrypt_with_pek(pek, enc_hash)
    md5 = Digest::MD5.new
    begin
      md5.update(pek)
      md5.update(enc_hash[0,16])
      rc4 = OpenSSL::Cipher::Cipher.new('rc4')
      rc4.key = md5.digest
      hash = rc4.update(enc_hash[16,enc_hash.size])
    rescue
      return "NO PASSWORD"
    end
    return hash
end

def decrypt_single_hash(rid, enc_hash)
  des_k1, des_k2 = sid_to_key(rid)
  d1 = OpenSSL::Cipher::Cipher.new('des-ecb')
  d1.padding = 0
  d1.key = des_k1
    
  d2 = OpenSSL::Cipher::Cipher.new('des-ecb')
  d2.padding = 0
  d2.key = des_k2
  
  p1 = d1.decrypt.update(enc_hash[0,8])
  p1 << d1.final
  
  p2 = d2.decrypt.update(enc_hash[8,enc_hash.length])
  p2 << d2.final
  hash = ""
  hash << p1 + p2
  return hash.unpack("H*")[0].to_s
end

 def sid_to_key(sid)
  s1 = ""
  s1 << (sid & 0xFF).chr
  s1 << ((sid >> 8) & 0xFF).chr
  s1 << ((sid >> 16) & 0xFF).chr
  s1 << ((sid >> 24) & 0xFF).chr
  s1 << s1[0]
  s1 << s1[1]
  s1 << s1[2]
  s2 = s1[3] + s1[0] + s1[1] + s1[2]
  s2 << s2[0] + s2[1] + s2[2]

  return string_to_key(s1), string_to_key(s2)
end

def string_to_key(s)
  key = []
  key << (s[0].unpack('C')[0] >> 1)
  key << ( ((s[0].unpack('C')[0]&0x01)<<6) | (s[1].unpack('C')[0]>>2) )
  key << ( ((s[1].unpack('C')[0]&0x03)<<5) | (s[2].unpack('C')[0]>>3) )
  key << ( ((s[2].unpack('C')[0]&0x07)<<4) | (s[3].unpack('C')[0]>>4) )
  key << ( ((s[3].unpack('C')[0]&0x0F)<<3) | (s[4].unpack('C')[0]>>5) )
  key << ( ((s[4].unpack('C')[0]&0x1F)<<2) | (s[5].unpack('C')[0]>>6) )
  key << ( ((s[5].unpack('C')[0]&0x3F)<<1) | (s[6].unpack('C')[0]>>7) )
  key << ( s[6].unpack('C')[0]&0x7F)
    
  0.upto(7).each do |i|
    key[i] = (key[i]<<1)
    key[i] = @parity[key[i]]
  end
    
  return key.pack("<C*")
end

@enc_pek = get_pek(@db)
@bootkey = get_boot_key(@sys)
@dec_pek = decrypt_pek(@bootkey, @enc_pek)

@db.each_line do |line|
	record = line.to_s.split("\t")
	encnthash = [record[@nthash].to_s[16,record[@nthash].size].to_s].pack("H*")
	enclmhash = [record[@lmhash].to_s[16,record[@lmhash].size].to_s].pack("H*")
	username = record[@username].to_s
	sid = record[@sid].to_s
	sid = [sid[sid.size - 8, sid.size]].pack("H*").unpack("N*")[0].to_i
	pek = record[@pek]
	if !enclmhash.to_s.empty? || !encnthash.to_s.empty?
	  nthash = decrypt_with_pek(@dec_pek, encnthash)
	  if nthash == "NO PASSWORD"
	    nthash = "31d6cfe0d16ae931b73c59d7e0c089c0"
	  else
      nthash = decrypt_single_hash(sid, nthash)
    end
	  lmhash = decrypt_with_pek(@dec_pek, enclmhash)
	  if lmhash == "NO PASSWORD"
	    lmhash = "aad3b435b51404eeaad3b435b51404ee"
	  else
	    lmhash = decrypt_single_hash(sid, lmhash)
	  end
	  puts username + ":" + sid.to_s + ":" + lmhash + ":" + nthash + ":::"
	end
end
