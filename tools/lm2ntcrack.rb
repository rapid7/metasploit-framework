#!/usr/bin/env ruby
#
# $Id$
#
# This script cracks any type of NTLM hash
# Credit to	-Yannick Hamon <yannick.hamon[at]xmcopartners.com> for the original idea/perl code
#		-Alexandre Maloteaux <a.maloteaux[at]gmail.com> for improvments
# $Revision$
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
require 'rex/proto/ntlm/crypt'

CRYPT = Rex::Proto::NTLM::Crypt

BRUTE_MODE = 1
HASH_MODE  = 2
PASS_MODE =  3

def usage
  $stderr.puts("\nUsage: #{$0} -t type <options>\n" + $args.usage)
  $stderr.puts("This tool can be use in 3 ways whatever type is choosen\n")
  $stderr.puts("-If only a password (-p) is provided, it will display the hash.\n")
  $stderr.puts("-If a password (-p) and an hash (-a) is provided, it will test the password against the hash.\n")
  $stderr.puts("-If a list of password (-l) is provided and an hash (-a), it will try to bruteforce the hash \n\n")
  exit
end

def permute_pw(pw)
  # fast permutation from http://stackoverflow.com/a/1398900
  perms = [""]
  if pw.nil?
    return perms
  end
  tail = pw.downcase
  while tail.length > 0 do
    head, tail, psize = tail[0..0], tail[1..-1], perms.size
    hu = head.upcase
    for i in (0...psize)
      tp = perms[i]
      perms[i] = tp + hu
      if hu != head
        perms.push(tp + head)
      end
    end
  end
  return perms
end

type = hash = pass = srvchal = clichal = calculatedhash = list = user = domain = nil

$args = Rex::Parser::Arguments.new(
  "-t" => [ true,  "The type of hash to crack : HALFLM/LM/NTLM/HALFNETLMv1/NETLMv1/NETNTLMv1/NETNTLM2_SESSION/NETLMv2/NETNTLMv2"	],
  "-a" => [ true,  "The hash to crack"                                          				],
  "-p" => [ true,  "The password "                                                            		],
  "-l" => [ true,  "The list of password to check against an hash"                               		],
  "-s" => [ true,  "The LM/NTLM Server Challenge (NET* type only)"		                   	],
  "-c" => [ true,  "The LM/NTLM Client Challenge (NETNTLM2_SESSION/NETLMv2/NETNTLMv2/ type only)"    		 	],
  "-u" => [ true,  "The user name                (NETLMv2/NETNTLMv2 type only)"     	],
  "-d" => [ true,  "The domain (machine) name    (NETLMv2/NETNTLMv2 type only)"     	],
  "-h" => [ false, "Display this help information"                                                   	])


$args.parse(ARGV) { |opt, idx, val|
  case opt
    when "-t"
      type = val
    when "-a"
      hash = val
    when "-p"
      pass = val
    when "-l"
      list = val
    when "-s"
      srvchal = val
    when "-c"
      clichal = val
    when "-u"
      user = val
    when "-d"
      domain = val
    when "-h"
      usage
    else
      usage
  end
}

if not type
  usage
else
  if pass and (not (hash or list))
    mode = HASH_MODE
  elsif pass and hash and not list
    mode = PASS_MODE
  elsif list and hash and not pass
    mode = BRUTE_MODE
    if not File.exist? list
      $stderr.puts "[*] The passwords list file does not exist"
      exit
    end
    if not File.file? list
      $stderr.puts "[*] The passwords list provided is not a file"
      exit
    end
    if not File.readable? list
      $stderr.puts "[*] The passwords list file is not readable"
      exit
    end
  else
    usage
  end
end


if type == "HALFLM" or type == "LM" or type == "NTLM" then
  if srvchal != nil or clichal != nil or user != nil or domain != nil  then
    $stderr.puts "[*] No challenge, user or domain must be provided with this type"
    exit
  end
elsif type == "HALFNETLMv1" or type == "NETLMv1" or type == "NETNTLMv1" then
  if clichal != nil  or user != nil or domain != nil then
    $stderr.puts "[*] Client challenge, user or domain must not be provided with this type"
    exit
  end
elsif type == "NETNTLM2_SESSION"  then
  if user != nil or domain != nil then
    $stderr.puts "[*] User or domain must not be provided with this type"
    exit
  end
end

case type
when "HALFLM"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] HALFLM HASH must be exactly 16 bytes of hexadecimal"
      exit
    end
    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
        password = line.gsub("\r\n",'').gsub("\n",'')
        if password =~ /^.{1,7}$/
          puts password
          calculatedhash = CRYPT::lm_hash(password,true).unpack("H*")[0].upcase
          if calculatedhash == hash.upcase
            puts "[*] Correct password found : #{password.upcase}"
            exit
          end
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    if not pass =~ /^.{0,7}$/
      $stderr.puts "[*] LM password can not be bigger then 7 characters"
      exit
    end
    calculatedhash = CRYPT::lm_hash(pass,true).unpack("H*")[0].upcase
    puts "[*] The LM hash for #{pass.upcase} is  : #{calculatedhash}"
    exit
  when PASS_MODE
    if not pass =~ /^.{0,7}$/
      $stderr.puts "[*] LM password can not be bigger then 7 characters"
      exit
    end
    if not hash =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] LM HASH must be exactly 16 bytes of hexadecimal"
      exit
    end
    calculatedhash = CRYPT::lm_hash(pass,true).unpack("H*")[0].upcase
    if hash.upcase == calculatedhash
      puts "[*] Correct password provided : #{pass.upcase}"
      exit
    else
      puts "[*] Incorrect password provided : #{pass.upcase}"
      exit
    end
  end

when "LM"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{32})$/
      $stderr.puts "[*] LM HASH must be exactly 32 bytes of hexadecimal"
      exit
    end
    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
        password = line.gsub("\r\n",'').gsub("\n",'')
        if password =~ /^.{1,14}$/
          puts password
          calculatedhash = CRYPT::lm_hash(password.upcase).unpack("H*")[0].upcase
          if calculatedhash == hash.upcase
            puts "[*] Correct password found : #{password.upcase}"
            exit
          end
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    if not pass =~ /^.{0,14}$/
      $stderr.puts "[*] LM password can not be bigger then 14 characters"
      exit
    end
    calculatedhash = CRYPT::lm_hash(pass.upcase).unpack("H*")[0].upcase
    puts "[*] The LM hash for #{pass.upcase} is  : #{calculatedhash}"
    exit
  when PASS_MODE
    if not pass =~ /^.{0,14}$/
      $stderr.puts "[*] LM password can not be bigger then 14 characters"
      exit
    end
    if not hash =~ /^([a-fA-F0-9]{32})$/
      $stderr.puts "[*] LM HASH must be exactly 32 bytes of hexadecimal"
      exit
    end
    calculatedhash = CRYPT::lm_hash(pass.upcase).unpack("H*")[0].upcase
    if hash.upcase == calculatedhash
      puts "[*] Correct password provided : #{pass.upcase}"
      exit
    else
      puts "[*] Incorrect password provided : #{pass.upcase}"
      exit
    end
  end

when "NTLM"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{32})$/
      $stderr.puts "[*] NTLM HASH must be exactly 32 bytes of hexadecimal"
      exit
    end
    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
        password = line.gsub("\r\n",'').gsub("\n",'')
        for permutedpw in permute_pw(password)
          puts permutedpw
          calculatedhash = CRYPT::ntlm_hash(permutedpw).unpack("H*")[0].upcase
          if calculatedhash == hash.upcase
            puts "[*] Correct password found : #{permutedpw}"
            exit
          end
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    calculatedhash = CRYPT::ntlm_hash(pass).unpack("H*")[0].upcase
    puts "[*] The NTLM hash for #{pass} is  : #{calculatedhash}"
    exit
  when PASS_MODE
    if not hash =~ /^([a-fA-F0-9]{32})$/
      $stderr.puts "[*] NTLM HASH must be exactly 32 bytes of hexadecimal"
      exit
    end
    for permutedpw in permute_pw(pass)
      calculatedhash = CRYPT::ntlm_hash(permutedpw).unpack("H*")[0].upcase
      if hash.upcase == calculatedhash
        puts "[*] Correct password provided : #{permutedpw}"
        exit
      end
    end
    puts "[*] Incorrect password provided : #{pass}"
  end
when  "HALFNETLMv1"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] NETLMv1 HASH must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
        password = line.gsub("\r\n",'').gsub("\n",'')
        if password =~ /^.{1,7}$/
          puts password
          #Rem : cause of the [0,7] there is only 1/256 chance that the guessed password will be the good one
          arglm = { 	:lm_hash => CRYPT::lm_hash(password,true)[0,7],
              :challenge => [ srvchal ].pack("H*") }
          calculatedhash = CRYPT::lm_response(arglm,true).unpack("H*")[0].upcase
          if calculatedhash == hash.upcase
            puts "[*] Correct password found : #{password.upcase}"
            exit
          end
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    if not pass =~ /^.{0,7}$/
      $stderr.puts "[*] HALFNETLMv1 password can not be bigger then 7 characters"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    arglm = { 	:lm_hash => CRYPT::lm_hash(pass,true)[0,7],
        :challenge => [ srvchal ].pack("H*") }

    calculatedhash = CRYPT::lm_response(arglm,true).unpack("H*")[0].upcase
    puts "[*] The HALFNETLMv1 hash for #{pass.upcase} is  : #{calculatedhash}"
    exit
  when PASS_MODE
    if not pass =~ /^.{0,7}$/
      $stderr.puts "[*] HALFNETLMv1 password can not be bigger then 7 characters"
      exit
    end
    if not hash =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] HALFNETLMv1 HASH must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    #Rem : cause of the [0,7] there is only 1/256 chance that the guessed password will be the good one
    arglm = { 	:lm_hash => CRYPT::lm_hash(pass,true)[0,7],
        :challenge => [ srvchal ].pack("H*") }

    calculatedhash = CRYPT::lm_response(arglm,true).unpack("H*")[0].upcase
    if hash.upcase == calculatedhash
      puts "[*] Correct password provided : #{pass.upcase}"
      exit
    else
      puts "[*] Incorrect password provided : #{pass.upcase}"
      exit
    end
  end
when  "NETLMv1"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{48})$/
      $stderr.puts "[*] NETLMv1 HASH must be exactly 48 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
        password = line.gsub("\r\n",'').gsub("\n",'')
        if password =~ /^.{1,14}$/
          puts password
          arglm = { 	:lm_hash => CRYPT::lm_hash(password),
              :challenge => [ srvchal ].pack("H*") }
          calculatedhash = CRYPT::lm_response(arglm).unpack("H*")[0].upcase
          if calculatedhash == hash.upcase
            puts "[*] Correct password found : #{password.upcase}"
            exit
          end
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    if not pass =~ /^.{1,14}$/
      $stderr.puts "[*] NETLMv1 password can not be bigger then 14 characters"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    arglm = { 	:lm_hash => CRYPT::lm_hash(pass),
        :challenge => [ srvchal ].pack("H*") }

    calculatedhash = CRYPT::lm_response(arglm).unpack("H*")[0].upcase
    puts "[*] The NETLMv1 hash for #{pass.upcase} is  : #{calculatedhash}"
    exit
  when PASS_MODE
    if not pass =~ /^.{1,14}$/
      $stderr.puts "[*] NETLMv1 password can not be bigger then 14 characters"
      exit
    end
    if not hash =~ /^([a-fA-F0-9]{48})$/
      $stderr.puts "[*] NETLMv1 HASH must be exactly 48 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    arglm = { 	:lm_hash => CRYPT::lm_hash(pass),
        :challenge => [ srvchal ].pack("H*") }

    calculatedhash = CRYPT::lm_response(arglm).unpack("H*")[0].upcase
    if hash.upcase == calculatedhash
      puts "[*] Correct password provided : #{pass.upcase}"
      exit
    else
      puts "[*] Incorrect password provided : #{pass.upcase}"
      exit
    end
  end
when "NETNTLMv1"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{48})$/
      $stderr.puts "[*] NETNTLMv1 HASH must be exactly 48 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
      password = line.gsub("\r\n",'').gsub("\n",'')
      for permutedpw in permute_pw(password)
        puts permutedpw
        argntlm = { 	:ntlm_hash =>  CRYPT::ntlm_hash(permutedpw),
            :challenge => [ srvchal ].pack("H*") }
        calculatedhash = CRYPT::ntlm_response(argntlm).unpack("H*")[0].upcase
          if calculatedhash == hash.upcase
            puts "[*] Correct password found : #{permutedpw}"
            exit
          end
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    argntlm = { 	:ntlm_hash =>  CRYPT::ntlm_hash(pass),
        :challenge => [ srvchal ].pack("H*") }
    calculatedhash = CRYPT::ntlm_response(argntlm).unpack("H*")[0].upcase
    puts "[*] The NETNTLMv1 hash for #{pass} is  : #{calculatedhash}"
    exit
  when PASS_MODE
    if not hash =~ /^([a-fA-F0-9]{48})$/
      $stderr.puts "[*] NETNTLMv1 HASH must be exactly 48 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    for permutedpw in permute_pw(pass)
      argntlm = { 	:ntlm_hash =>  CRYPT::ntlm_hash(permutedpw),
          :challenge => [ srvchal ].pack("H*") }

      calculatedhash = CRYPT::ntlm_response(argntlm).unpack("H*")[0].upcase
      if hash.upcase == calculatedhash
        puts "[*] Correct password provided : #{permutedpw}"
        exit
      end
    end
    puts "[*] Incorrect password provided : #{pass}"
    exit
  end
when  "NETNTLM2_SESSION"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{48})$/
      $stderr.puts "[*] NETNTLM2_SESSION HASH must be exactly 48 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Client challenge must be exactly 16 bytes of hexadecimal"
      exit
    end

    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
        password = line.gsub("\r\n",'').gsub("\n",'')
        for permutedpw in permute_pw(password)
          puts permutedpw
          argntlm = { 	:ntlm_hash =>  CRYPT::ntlm_hash(permutedpw),
              :challenge => [ srvchal ].pack("H*") }
          optntlm = {	:client_challenge => [ clichal ].pack("H*")}

          calculatedhash = CRYPT::ntlm2_session(argntlm,optntlm).join[24,24].unpack("H*")[0].upcase

          if calculatedhash == hash.upcase
            puts "[*] Correct password found : #{permutedpw}"
            exit
          end
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Client challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    argntlm = { 	:ntlm_hash =>  CRYPT::ntlm_hash(pass),
        :challenge => [ srvchal ].pack("H*") }
    optntlm = {	:client_challenge => [ clichal ].pack("H*")}

    calculatedhash = CRYPT::ntlm2_session(argntlm,optntlm).join[24,24].unpack("H*")[0].upcase
    puts "[*] The NETNTLM2_SESSION hash for #{pass} is  : #{calculatedhash}"
    exit
  when PASS_MODE
    if not hash =~ /^([a-fA-F0-9]{48})$/
      $stderr.puts "[*] NETNTLM2_SESSION HASH must be exactly 48 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Client challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    for permutedpw in permute_pw(pass)
      argntlm = { 	:ntlm_hash =>  CRYPT::ntlm_hash(permutedpw),
          :challenge => [ srvchal ].pack("H*") }
      optntlm = {	:client_challenge => [ clichal ].pack("H*")}

      calculatedhash = CRYPT::ntlm2_session(argntlm,optntlm).join[24,24].unpack("H*")[0].upcase

      if hash.upcase == calculatedhash
        puts "[*] Correct password provided : #{permutedpw}"
        exit
      end
    end
    puts "[*] Incorrect password provided : #{pass}"
    exit
  end
when  "NETLMv2"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{32})$/
      $stderr.puts "[*] NETLMv2 HASH must be exactly 32 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge mus be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Client challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not user
      $stderr.puts "[*] User name must be provided with this type"
      exit
    end
    if not domain
      $stderr.puts "[*] Domain name must be provided with this type"
      exit
    end

    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
        password = line.gsub("\r\n",'').gsub("\n",'')
        puts password
        arglm = {	:ntlmv2_hash =>  CRYPT::ntlmv2_hash(user,password, domain),
            :challenge => [ srvchal ].pack("H*") }
        optlm = {	:client_challenge => [ clichal ].pack("H*")}
        calculatedhash = CRYPT::lmv2_response(arglm, optlm).unpack("H*")[0].upcase
        if calculatedhash.slice(0,32) == hash.upcase
          puts "[*] Correct password found : #{password}"
          exit
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Client challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not user
      $stderr.puts "[*] User name must be provided with this type"
      exit
    end
    if not domain
      $stderr.puts "[*] Domain name must be provided with this type"
      exit
    end

    arglm = {	:ntlmv2_hash =>  CRYPT::ntlmv2_hash(user,pass, domain),
        :challenge => [ srvchal ].pack("H*") }
    optlm = {	:client_challenge => [ clichal ].pack("H*")}
    calculatedhash = CRYPT::lmv2_response(arglm, optlm).unpack("H*")[0].upcase

    puts "[*] The NETLMv2 hash for #{pass} is : #{calculatedhash.slice(0,32)}"
    exit
  when PASS_MODE
    if not hash =~ /^([a-fA-F0-9]{32})$/
      $stderr.puts "[*] NETLMv2 HASH must be exactly 32 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Client challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not user
      $stderr.puts "[*] User name must be provided with this type"
      exit
    end
    if not domain
      $stderr.puts "[*] Domain name must be provided with this type"
      exit
    end
    arglm = {	:ntlmv2_hash =>  CRYPT::ntlmv2_hash(user,pass, domain),
        :challenge => [ srvchal ].pack("H*") }
    optlm = {	:client_challenge => [ clichal ].pack("H*")}
    calculatedhash = CRYPT::lmv2_response(arglm, optlm).unpack("H*")[0].upcase
    if hash.upcase == calculatedhash.slice(0,32)
      puts "[*] Correct password provided : #{pass}"
      exit
    else
      puts "[*] Incorrect password provided : #{pass}"
      exit
    end
  end

when "NETNTLMv2"
  case mode
  when BRUTE_MODE
    if not hash =~ /^([a-fA-F0-9]{32})$/
      $stderr.puts "[*] NETNTLMv2 HASH must be exactly 32 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{17,})$/
      $stderr.puts "[*] Client challenge must be bigger then 16 bytes of hexadecimal"
      exit
    end
    if not user
      $stderr.puts "[*] User name must be provided with this type"
      exit
    end
    if not domain
      $stderr.puts "[*] Domain name must be provided with this type"
      exit
    end

    File.open(list,"rb") do |password_list|
      password_list.each_line do |line|
        password = line.gsub("\r\n",'').gsub("\n",'')
        for permutedpw in permute_pw(password)
          puts permutedpw
          argntlm = { 	:ntlmv2_hash =>  CRYPT::ntlmv2_hash(user, permutedpw, domain),
              :challenge => [ srvchal ].pack("H*") }
          optntlm = { 	:nt_client_challenge => [ clichal ].pack("H*")}
          calculatedhash = CRYPT::ntlmv2_response(argntlm,optntlm).unpack("H*")[0].upcase

          if calculatedhash.slice(0,32) == hash.upcase
            puts "[*] Correct password found : #{password}"
            exit
          end
        end
      end
    end
    puts "[*] No password found"
    exit
  when HASH_MODE
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{17,})$/
      $stderr.puts "[*] Client challenge must be bigger then 16 bytes of hexadecimal"
      exit
    end
    if not user
      $stderr.puts "[*] User name must be provided with this type"
      exit
    end
    if not domain
      $stderr.puts "[*] Domain name must be provided with this type"
      exit
    end

    argntlm = { 	:ntlmv2_hash =>  CRYPT::ntlmv2_hash(user, pass, domain),
        :challenge => [ srvchal ].pack("H*") }
    optntlm = { 	:nt_client_challenge => [ clichal ].pack("H*")}
    calculatedhash = CRYPT::ntlmv2_response(argntlm,optntlm).unpack("H*")[0].upcase

    puts "[*] The NETNTLMv2 hash for #{pass} is : #{calculatedhash.slice(0,32)}"
    exit
  when PASS_MODE
    if not hash =~ /^([a-fA-F0-9]{32})$/
      $stderr.puts "[*] NETNTLMv2 HASH must be exactly 32 bytes of hexadecimal"
      exit
    end
    if not srvchal
      $stderr.puts "[*] Server challenge must be provided with this type"
      exit
    end
    if not srvchal =~ /^([a-fA-F0-9]{16})$/
      $stderr.puts "[*] Server challenge must be exactly 16 bytes of hexadecimal"
      exit
    end
    if not clichal
      $stderr.puts "[*] Client challenge must be provided with this type"
      exit
    end
    if not clichal =~ /^([a-fA-F0-9]{17,})$/
      $stderr.puts "[*] Client challenge must be bigger then 16 bytes of hexadecimal"
      exit
    end
    if not user
      $stderr.puts "[*] User name must be provided with this type"
      exit
    end
    if not domain
      $stderr.puts "[*] Domain name must be provided with this type"
      exit
    end

    for permutedpw in permute_pw(password)
      argntlm = { 	:ntlmv2_hash =>  CRYPT::ntlmv2_hash(user, permutedpw, domain),
          :challenge => [ srvchal ].pack("H*") }
      optntlm = { 	:nt_client_challenge => [ clichal ].pack("H*")}
      calculatedhash = CRYPT::ntlmv2_response(argntlm,optntlm).unpack("H*")[0].upcase

      if hash.upcase == calculatedhash.slice(0,32)
        puts "[*] Correct password provided : #{permutedpw}"
        exit
      end
    end
    puts "[*] Incorrect password provided : #{pass}"
    exit
  end
else
  $stderr.puts "type must be of type : HALFLM/LM/NTLM/HALFNETLMv1/NETLMv1/NETNTLMv1/NETNTLM2_SESSION/NETLMv2/NETNTLMv2"
  exit
end


