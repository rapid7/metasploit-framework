# -*- coding: binary -*-
require 'open3'
require 'fileutils'
require 'rex/proto/ntlm/crypt'



module Msf

###
#
# This module provides methods for working with John the Ripper
#
###
module Auxiliary::JohnTheRipper
  include Msf::Auxiliary::Report

  #
  # Initializes an instance of an auxiliary module that calls out to John the Ripper (jtr)
  #

  def initialize(info = {})
    super

    register_options(
      [
        OptPath.new('JOHN_BASE', [false, 'The directory containing John the Ripper (src, run, doc)']),
        OptPath.new('JOHN_PATH', [false, 'The absolute path to the John the Ripper executable']),
        OptPath.new('Wordlist', [false, 'The path to an optional Wordlist']),
        OptBool.new('Munge',[false, 'Munge the Wordlist (Slower)', false])
      ], Msf::Auxiliary::JohnTheRipper
    )

    @run_path  = nil
    @john_path = ::File.join(Msf::Config.install_root, "data", "john")

    autodetect_platform
  end

  def autodetect_platform
    cpuinfo_base = ::File.join(Msf::Config.install_root, "data", "cpuinfo")
    return @run_path if @run_path

    if File.directory?(cpuinfo_base)
      case ::RUBY_PLATFORM
      when /mingw|cygwin|mswin/
        data = `"#{cpuinfo_base}/cpuinfo.exe"` rescue nil
        case data
        when /sse2/
          @run_path ||= "run.win32.sse2/john.exe"
        when /mmx/
          @run_path ||= "run.win32.mmx/john.exe"
        else
          @run_path ||= "run.win32.any/john.exe"
        end

      when /x86_64-linux/
        ::FileUtils.chmod(0755, "#{cpuinfo_base}/cpuinfo.ia64.bin") rescue nil
        data = `#{cpuinfo_base}/cpuinfo.ia64.bin` rescue nil
        case data
        when /mmx/
          @run_path ||= "run.linux.x64.mmx/john"
        else
          @run_path ||= "run.linux.x86.any/john"
        end
        
      when /i[\d]86-linux/
        ::FileUtils.chmod(0755, "#{cpuinfo_base}/cpuinfo.ia32.bin") rescue nil
        data = `#{cpuinfo_base}/cpuinfo.ia32.bin` rescue nil
        case data
        when /sse2/
          @run_path ||= "run.linux.x86.sse2/john"
        when /mmx/
          @run_path ||= "run.linux.x86.mmx/john"
        else
          @run_path ||= "run.linux.x86.any/john"
        end
      end
    end
    @run_path
  end

  def john_session_id
    @session_id ||= ::Rex::Text.rand_text_alphanumeric(8)
  end

  def john_pot_file
    ::File.join( ::Msf::Config.config_directory, "john.pot" )
  end

  def john_cracked_passwords
    ret = {}
    return ret if not ::File.exist?(john_pot_file)
    ::File.open(john_pot_file, "rb") do |fd|
      fd.each_line do |line|
        hash,clear = line.sub(/\r?\n$/, '').split(",", 2)
        ret[hash] = clear
      end
    end
    ret
  end

  def john_show_passwords(hfile, format=nil)
    res = {:cracked => 0, :uncracked => 0, :users => {} }

    john_command = john_binary_path

    if john_command.nil?
      print_error("John the Ripper executable not found")
      return res
    end

    pot  = john_pot_file
    conf = ::File.join(john_base_path, "confs", "john.conf")

    cmd = [ john_command,  "--show", "--conf=#{conf}", "--pot=#{pot}", hfile]

    if format
      cmd << "--format=" + format
    end

    if RUBY_VERSION =~ /^1\.8\./
      cmd = cmd.join(" ")
    end

    ::IO.popen(cmd, "rb") do |fd|
      fd.each_line do |line|
        print_status(line)
        if line =~ /(\d+) password hash(es)* cracked, (\d+) left/m
          res[:cracked]   = $1.to_i
          res[:uncracked] = $2.to_i
        end

        bits = line.split(':')
        next if not bits[2]
        if (format== 'lm' or format == 'nt')
          res[ :users ][ bits[0] ] = bits[1]
        else
          bits.last.chomp!
          res[ :users ][ bits[0] ] = bits.drop(1)
        end

      end
    end
    res
  end

  def john_unshadow(passwd_file,shadow_file)

    retval=""

    john_command = john_binary_path

    if john_command.nil?
      print_error("John the Ripper executable not found")
      return nil
    end

    if File.exists?(passwd_file)
      unless File.readable?(passwd_file)
        print_error("We do not have permission to read #{passwd_file}")
        return nil
      end
    else
      print_error("File does not exist: #{passwd_file}")
      return nil
    end

    if File.exists?(shadow_file)
      unless File.readable?(shadow_file)
        print_error("We do not have permission to read #{shadow_file}")
        return nil
      end
    else
      print_error("File does not exist: #{shadow_file}")
      return nil
    end


    cmd = [ john_command.gsub(/john$/, "unshadow"), passwd_file , shadow_file ]

    if RUBY_VERSION =~ /^1\.8\./
      cmd = cmd.join(" ")
    end
    ::IO.popen(cmd, "rb") do |fd|
      fd.each_line do |line|
        retval << line
      end
    end
    return retval
  end

  def john_wordlist_path
    ::File.join(john_base_path, "wordlists", "password.lst")
  end

  def john_binary_path
    path = nil
    if datastore['JOHN_PATH'] and ::File.file?(datastore['JOHN_PATH'])
      path = datastore['JOHN_PATH']
      ::FileUtils.chmod(0755, path) rescue nil
    end

    if not @run_path
      if ::RUBY_PLATFORM =~ /mingw|cygwin|mswin/
        ::File.join(john_base_path, "john.exe")
      else
        path = ::File.join(john_base_path, "john")
        ::FileUtils.chmod(0755, path) rescue nil
      end
    else
      path = ::File.join(john_base_path, @run_path)
      ::FileUtils.chmod(0755, path) rescue nil
    end

    if path and ::File.exists?(path)
      return path
    end

    path = Rex::FileUtils.find_full_path("john") ||
      Rex::FileUtils.find_full_path("john.exe")
  end

  def john_base_path
    if datastore['JOHN_BASE'] and ::File.directory?(datastore['JOHN_BASE'])
      return datastore['JOHN_BASE']
    end
    if datastore['JOHN_PATH'] and ::File.file?(datastore['JOHN_PATH'])
      return ::File.dirname( datastore['JOHN_PATH'] )
    end
    @john_path
  end

  def john_expand_word(str)
    res = [str]
    str.split(/\W+/) {|w| res << w }
    res.uniq
  end

  def john_lm_upper_to_ntlm(pwd, hash)
    pwd  = pwd.upcase
    hash = hash.upcase
    Rex::Text.permute_case(pwd).each do |str|
      if hash == Rex::Proto::NTLM::Crypt.ntlm_hash(str).unpack("H*")[0].upcase
        return str
      end
    end
    nil
  end


  def john_crack(hfile, opts={})

    res = {:cracked => 0, :uncracked => 0, :users => {} }

    john_command = john_binary_path

    if john_command.nil?
      print_error("John the Ripper executable not found")
      return nil
    end

    # Don't bother making a log file, we'd just have to rm it when we're
    # done anyway.
    cmd = [ john_command,  "--session=" + john_session_id, "--nolog"]

    if opts[:conf]
      cmd << ( "--conf=" + opts[:conf] )
    else
      cmd << ( "--conf=" + ::File.join(john_base_path, "confs", "john.conf") )
    end

    if opts[:pot]
      cmd << ( "--pot=" + opts[:pot] )
    else
      cmd << ( "--pot=" + john_pot_file )
    end

    if opts[:format]
      cmd << ( "--format=" + opts[:format] )
    end

    if opts[:wordlist]
      cmd << ( "--wordlist=" + opts[:wordlist] )
    end

    if opts[:incremental]
      cmd << ( "--incremental=" + opts[:incremental] )
    end

    if opts[:single]
      cmd << ( "--single=" + opts[:single] )
    end

    if opts[:rules]
      cmd << ( "--rules=" + opts[:rules] )
    end

    cmd << hfile

    if RUBY_VERSION =~ /^1\.8\./
      cmd = cmd.join(" ")
    end

    ::IO.popen(cmd, "rb") do |fd|
      fd.each_line do |line|
        print_status("Output: #{line.strip}")
      end
    end

    res
  end

  def build_seed

    seed = []
    #Seed the wordlist with Database , Table, and Instance Names

    count = 0
    schemas = myworkspace.notes.where('ntype like ?', '%.schema%')
    unless schemas.nil? or schemas.empty?
      schemas.each do |anote|
        seed << anote.data['DBName']
        count += 1
        anote.data['Tables'].each do |table|
          seed << table['TableName']
          count += 1
          table['Columns'].each do |column|
            seed << column['ColumnName']
            count += 1
          end
        end
      end
    end
    print_status "Seeding wordlist with DB schema info... #{count} words added"
    count = 0

    instances = myworkspace.notes.find(:all, :conditions => ['ntype=?', 'mssql.instancename'])
    unless instances.nil? or instances.empty?
      instances.each do |anote|
        seed << anote.data['InstanceName']
        count += 1
      end
    end
    print_status "Seeding with MSSQL Instance Names....#{count} words added"
    count = 0

    # Seed the wordlist with usernames, passwords, and hostnames

    myworkspace.hosts.find(:all).each do |o|
      if o.name
        seed << john_expand_word( o.name )
        count += 1
      end
    end
    print_status "Seeding with hostnames....#{count} words added"
    count = 0


    myworkspace.creds.each do |o|
      if o.user
        seed << john_expand_word( o.user )
        count +=1
      end
      if (o.pass and o.ptype !~ /hash/)
        seed << john_expand_word( o.pass )
        count += 1
      end
    end
    print_status "Seeding with found credentials....#{count} words added"
    count = 0

    # Grab any known passwords out of the john.pot file
    john_cracked_passwords.values do |v|
      seed << v
      count += 1
    end
    print_status "Seeding with cracked passwords from John....#{count} words added"
    count = 0

    #Grab the default John Wordlist
    john = File.open(john_wordlist_path, "rb")
    john.each_line do |line|
      seed << line.chomp
      count += 1
    end
    print_status "Seeding with default John wordlist...#{count} words added"
    count = 0

    if datastore['Wordlist']
      wordlist= File.open(datastore['Wordlist'], "rb")
      wordlist.each_line do |line|
        seed << line.chomp
        count ==1
      end
      print_status "Seeding from user supplied wordlist...#{count} words added"
    end



    unless seed.empty?
      seed.flatten!
      seed.uniq!
      if datastore['Munge']
        mungedseed=[]
        seed.each do |word|
          munged = word.gsub(/[sS]/, "$").gsub(/[aA]/,"@").gsub(/[oO]/,"0")
          mungedseed << munged
          munged.gsub!(/[eE]/, "3")
          munged.gsub!(/[tT]/, "7")
          mungedseed << munged
        end
        print_status "Adding #{mungedseed.count} words from munging..."
        seed << mungedseed
        seed.flatten!
        seed.uniq!
      end
    end
    print_status "De-duping the wordlist...."

    print_status("Wordlist Seeded with #{seed.length} words")

    return seed

  end
end
end
