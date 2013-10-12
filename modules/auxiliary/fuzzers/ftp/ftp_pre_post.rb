##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize
    super(
      'Name'           => 'Simple FTP Fuzzer',
      'Description'    => %q{
        This module will connect to a FTP server and perform pre- and post-authentication fuzzing
      },
      'Author'         => [ 'corelanc0d3r <peter.ve[at]corelan.be>', 'jduck' ],
      'License'        => MSF_LICENSE
      )

    register_options(
      [
        Opt::RPORT(21),
        OptInt.new('STARTATSTAGE', [ false, "Start at this test stage",1]),
        OptInt.new('STEPSIZE', [ false, "Increase string size each iteration with this number of chars",10]),
        OptInt.new('DELAY', [ false, "Delay between connections in seconds",1]),
        OptInt.new('STARTSIZE', [ false, "Fuzzing string startsize",10]),
        OptInt.new('ENDSIZE', [ false, "Fuzzing string endsize",20000]),
        OptInt.new('STOPAFTER', [ false, "Stop after x number of consecutive errors",2]),
        OptString.new('USER', [ false, "Username",'anonymous']),
        OptString.new('PASS', [ false, "Password",'mozilla@example.com']),
        OptBool.new('FASTFUZZ', [ false, "Only fuzz with cyclic pattern",true]),
        OptBool.new('CONNRESET', [ false, "Break on CONNRESET error",true]),
      ], self.class)
    deregister_options('RHOST')

    @evilchars = [
      'A','a','%s','%d','%n','%x','%p','-1','0','0xfffffffe','0xffffffff','A/','//','/..','//..',
      'A%20','./A','.A',',A','A:','!A','&A','?A','\A','../A/','..?','//A:','\\A','{A','$A','A*',
      'cmd','A@a.com','#A','A/../','~','~A','~A/','A`/','>A','<A','A%n','A../','.././','A../',
      '....//','~?*/','.\../','\.//A','-%A','%Y','%H','/1','!','@','%','&','/?(*','*','(',')',
      '`',',','~/','/.','\$:','/A~%n','=','=:;)}','1.2.','41414141','-1234','999999,','%00','+A',
      '+123','..\'','??.','..\.\'','.../','1234123+',
      '%Y%%Y%/','%FC%80%80%80%80%AE%FC%80%80%80%80%AE/','????/','\uff0e/','%%32%65%%32%65/',
      '+B./','%%32%65%%32%65/','..%c0%af','..%e0%80%af','..%c1%9c'
    ]
    @commands = [
      'ABOR','ACCT','ALLO','APPE','AUTH','CWD','CDUP','DELE','FEAT','HELP','HOST','LANG','LIST',
      'MDTM','MKD','MLST','MODE','NLST','NLST -al','NOOP','OPTS','PASV','PORT','PROT','PWD','REIN',
      'REST','RETR','RMD','RNFR','RNTO','SIZE','SITE','SITE CHMOD','SITE CHOWN','SITE EXEC','SITE MSG',
      'SITE PSWD','SITE ZONE','SITE WHO','SMNT','STAT','STOR','STOU','STRU','SYST','TYPE','XCUP',
      'XCRC','XCWD','XMKD','XPWD','XRMD'
    ]
    @emax = @evilchars.length

    register_advanced_options(
      [
        OptString.new('FtpCommands', [ false, "Commands to fuzz at stages 4 and 5",@commands.join(" ")]),
        OptBool.new('ExpandCrash', [ false, "Expand any crash strings",false]),
    ], self.class)
  end


  def get_pkt
    buf = sock.get
    vprint_status("[in ] #{buf.inspect}")
    buf
  end

  def send_pkt(pkt, get_resp = false)
    vprint_status("[out] #{pkt.inspect}")
    sock.put(pkt)
    get_pkt if get_resp
  end


  def process_phase(phase_num, phase_name, prepend = '', initial_cmds = [])
    print_status("[Phase #{phase_num}] #{phase_name} - #{Time.now.localtime}")
    ecount = 1
    @evilchars.each do |evilstr|

      if datastore['FASTFUZZ']
        evilstr = "Cyclic"
        @emax = 1
      end

      if (@stopprocess == false)
        count = datastore['STARTSIZE']
        print_status(" Character : #{evilstr} (#{ecount}/#{@emax})")
        ecount += 1
        while count <= datastore['ENDSIZE']
          begin
            connect
            if datastore['FASTFUZZ']
              evil = Rex::Text.pattern_create(count)
            else
              evil = evilstr * count
            end
            print_status("  -> Fuzzing size set to #{count} (#{prepend}#{evilstr})")
            initial_cmds.each do |cmd|
              send_pkt(cmd, true)
            end
            pkt = prepend + evil + "\r\n"
            send_pkt(pkt, true)
            sock.put("QUIT\r\n")
            Rex.sleep(datastore['DELAY'])
            disconnect

            count += datastore['STEPSIZE']

          rescue ::Exception => e
            @error_cnt += 1
            print_status("Exception #{@error_cnt} of #{@nr_errors}")
            if (e.class.name == 'Rex::ConnectionRefused') or (e.class.name == 'EOFError') or (e.class.name == 'Errno::ECONNRESET' and datastore['CONNRESET']) or (e.class.name == 'Errno::EPIPE')
              if datastore['ExpandCrash']
                print_status("Crash string : #{prepend}#{evil}")
              else
                print_status("Crash string : #{prepend}#{evilstr} x #{count}")
              end
              if @error_cnt >= @nr_errors
                print_status("System does not respond - exiting now\n")
                @stopprocess = true
                print_error("Error: #{e.class} #{e} #{e.backtrace}\n")
                return
              else
                print_status("Exception triggered, need #{@nr_errors - @error_cnt} more exception(s) before interrupting process")
                Rex.sleep(3)  #wait 3 seconds
              end
            end
            if @error_cnt >= @nr_errors
              count += datastore['STEPSIZE']
              @error_cnt = 0
            end
          end
        end
      end
    end
  end

  def ftp_commands
    if datastore['FtpCommands'].to_s.upcase == "DEFAULT"
      @commands
    else
      datastore['FtpCommands'].split(/[\s,]+/)
    end
  end

  def run_host(ip)

    startstage = datastore['STARTATSTAGE']

    @nr_errors = datastore['STOPAFTER']
    @error_cnt = 0
    @stopprocess = false

    if datastore['FASTFUZZ']
      @evilchars = ['']
    end

    print_status("Connecting to host " + ip + " on port " + datastore['RPORT'].to_s)

    if (startstage == 1)
      process_phase(1, "Fuzzing without command")
      startstage += 1
    end

    if (startstage == 2) and (@stopprocess == false)
      process_phase(2, "Fuzzing USER", 'USER ')
      startstage += 1
    end

    if (startstage == 3) and (@stopprocess == false)
      process_phase(3, "Fuzzing PASS", 'PASS ',
        [ "USER " + datastore['USER'] + "\r\n" ])
      startstage += 1
    end

    if (startstage == 4)
      print_status "[Phase 4] Fuzzing commands: #{ftp_commands.join(", ")}"
      ftp_commands().each do |cmd|
        if (@stopprocess == false)
          process_phase(4, "Fuzzing command: #{cmd}", "#{cmd} ",
            [
              "USER " + datastore['USER'] + "\r\n",
              "PASS " + datastore['PASS'] + "\r\n"
            ])
        end
      end
      # Don't progress into stage 5, it must be selected manually.
      #startstage += 1
    end

    # Fuzz other commands, all command combinations in one session
    if (startstage == 5)
      print_status("[Phase 5] Fuzzing other commands (Part 2, #{Time.now.localtime}): #{ftp_commands.join(", ")}")
      ftp_commands().each do |cmd|
        if (@stopprocess == false)
          ecount = 1
          count = datastore['STARTSIZE']
          print_status("Fuzzing command #{cmd} - #{Time.now.localtime}" )

          connect
          pkt = "USER " + datastore['USER'] + "\r\n"
          send_pkt(pkt, true)
          pkt = "PASS " + datastore['PASS'] + "\r\n"
          send_pkt(pkt, true)

          while count <= datastore['ENDSIZE']
            print_status("  -> Fuzzing size set to #{count}")
            begin
              @evilchars.each do |evilstr|
                if datastore['FASTFUZZ']
                  evilstr = "Cyclic"
                  evil = Rex::Text.pattern_create(count)
                  @emax = 1
                  ecount = 1
                else
                  evil = evilstr * count
                end
                print_status(" Command : #{cmd}, Character : #{evilstr} (#{ecount}/#{@emax})")
                ecount += 1
                pkt = cmd + " " + evil + "\r\n"
                send_pkt(pkt, true)
                Rex.sleep(datastore['DELAY'])
                @error_cnt = 0
              end
            rescue ::Exception => e
              @error_cnt += 1
              print_status("Exception #{@error_cnt} of #{@nr_errors}")
              if (e.class.name == 'Rex::ConnectionRefused') or (e.class.name == 'EOFError') or (e.class.name == 'Errno::ECONNRESET' and datastore['CONNRESET']) or (e.class.name == 'Errno::EPIPE')
                if @error_cnt >= @nr_errors
                  print_status("System does not respond - exiting now\n")
                  @stopprocess = true
                  print_error("Error: #{e.class} #{e} #{e.backtrace}\n")
                  return
                else
                  print_status("Exception triggered, need #{@nr_errors - @error_cnt} more exception(s) before interrupting process")
                  Rex.sleep(3)  #wait 3 seconds
                end
              end
              if @error_cnt >= @nr_errors
                @error_cnt = 0
              end
            end
            count += datastore['STEPSIZE']
          end
          sock.put("QUIT\r\n")
          Rex.sleep(datastore['DELAY'])
          disconnect
        end
      end
    end
  end

end
