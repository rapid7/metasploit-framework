##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
#
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'				=> 'John the Ripper Password Cracker (Fast Mode)',
      'Description'       => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired as hashed files (loot) or raw LANMAN/NTLM hashes (hashdump). The goal
        of this module is to find trivial passwords in a short amount of time. To
        crack complex passwords or use large wordlists, John the Ripper should be
        used outside of Metasploit. This initial version just handles LM/NTLM credentials
        from hashdump and uses the standard wordlist and rules.
      },
      'Author'			=> 'hdm',
      'License'			=> MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )
  end

  def run
    wordlist = Rex::Quickfile.new("jtrtmp")
    hashlist = Rex::Quickfile.new("jtrtmp")

    begin
      # Seed the wordlist with usernames, passwords, and hostnames
      seed = []

      myworkspace.hosts.find(:all).each {|o| seed << john_expand_word( o.name ) if o.name }
      myworkspace.creds.each do |o|
        seed << john_expand_word( o.user ) if o.user
        seed << john_expand_word( o.pass ) if (o.pass and o.ptype !~ /hash/)
      end

      # Grab any known passwords out of the john.pot file
      john_cracked_passwords.values {|v| seed << v }

      # Write the seed file
      wordlist.write( seed.flatten.uniq.join("\n") + "\n" )

      print_status("Seeded the password database with #{seed.length} words...")

      # Append the standard JtR wordlist as well
      ::File.open(john_wordlist_path, "rb") do |fd|
        wordlist.write fd.read(fd.stat.size)
      end

      # Close the wordlist to prevent sharing violations (windows)
      wordlist.close

      # Create a PWDUMP style input file for SMB Hashes
      smb_hashes = myworkspace.creds.select{|x| x.ptype == "smb_hash" }
      smb_hashes.each do |cred|
        hashlist.write( "cred_#{cred[:id]}:#{cred[:id]}:#{cred[:pass]}:::\n" )
      end
      hashlist.close

      if smb_hashes.length > 0
        cracked_ntlm = {}
        cracked_lm   = {}
        added        = []

        # Crack this in LANMAN format using wordlist mode with tweaked rules
        john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'lm')

        # Crack this in LANMAN format using various incremntal modes
        john_crack(hashlist.path, :incremental => "All4", :format => 'lm')
        john_crack(hashlist.path, :incremental => "Digits5", :format => 'lm')

        # Parse cracked passwords and permute LANMAN->NTLM as needed
        cracked = john_show_passwords(hashlist.path, 'lm')
        cracked[:users].each_pair do |k,v|
          next if v == ""
          next if (v[0,7] == "???????" or v[7,7] == "???????")
          next if not k =~ /^cred_(\d+)/m
          cid  = $1.to_i

          cracked_lm[k] = v

          cred_find = smb_hashes.select{|x| x[:id] == cid}
          next if cred_find.length == 0

          cred = cred_find.first
          ntlm = cred.pass.split(":", 2).last
          done = john_lm_upper_to_ntlm(v, ntlm)
          cracked_ntlm[k] = done if done
        end

        # Append any cracked values to the wordlist
        tfd = ::File.open(wordlist.path, "ab")
        cracked_lm.values.each   {|w| if not added.include?(w); tfd.write( w + "\n" ); added << w; end }
        cracked_ntlm.values.each {|w| if not added.include?(w); tfd.write( w + "\n" ); added << w; end }
        tfd.close

        # Crack this in NTLM format
        john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'nt')

        # Crack this in NTLM format using various incremntal modes
        john_crack(hashlist.path, :incremental => "All4", :format => 'nt')
        john_crack(hashlist.path, :incremental => "Digits5", :format => 'nt')

        # Parse cracked passwords
        cracked = john_show_passwords(hashlist.path, 'nt')
        cracked[:users].each_pair do |k,v|
          next if cracked_ntlm[k]
          cracked_ntlm[k] = v
        end

        # Append any cracked values to the wordlist
        tfd = ::File.open(wordlist.path, "ab")
        cracked_ntlm.values.each {|w| if not added.include?(w); tfd.write( w + "\n" ); added << w; end }
        tfd.close

        # Store the cracked results based on user_id => cred.id
        cracked_ntlm.each_pair do |k,v|
          next if not k =~ /^cred_(\d+)/m
          cid = $1.to_i

          cred_find = smb_hashes.select{|x| x[:id] == cid}
          next if cred_find.length == 0
          cred = cred_find.first
          next if cred.user.to_s.strip.length == 0

          print_good("Cracked: #{cred.user}:#{v} (#{cred.service.host.address}:#{cred.service.port})")
          report_auth_info(
            :host  => cred.service.host,
            :service => cred.service,
            :user  => cred.user,
            :pass  => v,
            :type  => "password",
            :source_id   => cred[:id],
            :source_type => 'cracked'
          )
        end
      end

      # XXX: Enter other hash types here (shadow, etc)

    rescue ::Timeout::Error
    ensure
      wordlist.close rescue nil
      hashlist.close rescue nil
      ::File.unlink(wordlist.path) rescue nil
      ::File.unlink(hashlist.path) rescue nil
    end
  end
end
