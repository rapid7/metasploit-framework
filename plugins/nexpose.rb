require 'English'
require 'nexpose'

module Msf
  Nexpose_yaml = "#{Msf::Config.config_directory}/nexpose.yaml".freeze # location of the nexpose.yml containing saved nexpose creds

  # This plugin provides integration with Rapid7 Nexpose
  class Plugin::Nexpose < Msf::Plugin
    class NexposeCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        'Nexpose'
      end

      def commands
        {
          'nexpose_connect' => 'Connect to a running Nexpose instance ( user:pass@host[:port] )',
          'nexpose_save' => 'Save credentials to a Nexpose instance',
          'nexpose_activity' => 'Display any active scan jobs on the Nexpose instance',

          'nexpose_scan' => 'Launch a Nexpose scan against a specific IP range and import the results',
          'nexpose_discover' => 'Launch a scan but only perform host and minimal service discovery',
          'nexpose_exhaustive' => 'Launch a scan covering all TCP ports and all authorized safe checks',
          'nexpose_dos' => 'Launch a scan that includes checks that can crash services and devices (caution)',

          'nexpose_disconnect' => 'Disconnect from an active Nexpose instance',

          'nexpose_sites' => 'List all defined sites',
          'nexpose_site_devices' => 'List all discovered devices within a site',
          'nexpose_site_import' => 'Import data from the specified site ID',
          'nexpose_report_templates' => 'List all available report templates',
          'nexpose_command' => 'Execute a console command on the Nexpose instance',
          'nexpose_sysinfo' => 'Display detailed system information about the Nexpose instance'

          # @TODO:
          # nexpose_stop_scan
        }
      end

      def nexpose_verify_db
        if !(framework.db && framework.db.usable && framework.db.active)
          print_error('No database has been configured, please use db_connect first')
          return false
        end

        true
      end

      def nexpose_verify
        return false if !nexpose_verify_db

        if !@nsc
          print_error("No active Nexpose instance has been configured, please use 'nexpose_connect'")
          return false
        end

        true
      end

      def cmd_nexpose_save(*args)
        # if we are logged in, save session details to nexpose.yaml
        if args[0] == '-h'
          print_status('Usage: ')
          print_status('       nexpose_save')
          return
        end

        if args[0]
          print_status('Usage: ')
          print_status('       nexpose_save')
          return
        end

        group = 'default'

        if ((@user && !@user.empty?) && (@host && !@host.empty?) && (@port && !@port.empty? && (@port.to_i > 0)) && (@pass && !@pass.empty?))
          config = { group.to_s => { 'username' => @user, 'password' => @pass, 'server' => @host, 'port' => @port, 'trust_cert' => @trust_cert } }
          ::File.open(Nexpose_yaml.to_s, 'wb') { |f| f.puts YAML.dump(config) }
          print_good("#{Nexpose_yaml} created.")
        else
          print_error('Missing username/password/server/port - relogin and then try again.')
          return
        end
      end

      def cmd_nexpose_connect(*args)
        return if !nexpose_verify_db

        if !args[0] && ::File.readable?(Nexpose_yaml.to_s)
          lconfig = YAML.load_file(Nexpose_yaml.to_s)
          @user = lconfig['default']['username']
          @pass = lconfig['default']['password']
          @host = lconfig['default']['server']
          @port = lconfig['default']['port']
          @trust_cert = lconfig['default']['trust_cert']
          unless @trust_cert
            @sslv = 'ok' # TODO: Not super-thrilled about bypassing the SSL warning...
          end
          nexpose_login
          return
        end

        if (args.empty? || args[0].empty? || (args[0] == '-h'))
          nexpose_usage
          return
        end

        @user = @pass = @host = @port = @sslv = @trust_cert = @trust_cert_file = nil

        case args.length
        when 1, 2
          cred, _split, targ = args[0].rpartition('@')
          @user, @pass = cred.split(':', 2)
          targ ||= '127.0.0.1:3780'
          @host, @port = targ.split(':', 2)
          @port ||= '3780'
          unless args.length == 1
            @trust_cert_file = args[1]
            if File.exist? @trust_cert_file
              @trust_cert = File.read(@trust_cert_file)
            else
              @sslv = @trust_cert_file
            end
          end
        when 4, 5
          @user, @pass, @host, @port, @trust_cert = args
          unless args.length == 4
            @trust_cert_file = @trust_cert
            if File.exist? @trust_cert_file
              @trust_cert = File.read(@trust_cert_file)
            else
              @sslv = @trust_cert_file
            end
          end
        else
          nexpose_usage
          return
        end
        nexpose_login
      end

      def nexpose_usage
        print_status('Usage: ')
        print_status('       nexpose_connect username:password@host[:port] <ssl-confirm || trusted_cert_file>')
        print_status('        -OR- ')
        print_status('       nexpose_connect username password host port <ssl-confirm || trusted_cert_file>')
      end

      def nexpose_login
        if !((@user && !@user.empty?) && (@host && !@host.empty?) && (@port && !@port.empty? && (@port.to_i > 0)) && (@pass && !@pass.empty?))
          nexpose_usage
          return
        end

        if ((@host != 'localhost') && (@host != '127.0.0.1') && (@trust_cert.nil? && @sslv != 'ok'))
          # consider removing this message and replacing with check on trust_store, and if trust_store is not found validate @host already has a truly trusted cert?
          print_error('Warning: SSL connections are not verified in this release, it is possible for an attacker')
          print_error('         with the ability to man-in-the-middle the Nexpose traffic to capture the Nexpose')
          print_error("         credentials. If you are running this on a trusted network, please pass in 'ok'")
          print_error('         as an additional parameter to this command.')
          return
        end

        # Wrap this so a duplicate session does not prevent a new login
        begin
          cmd_nexpose_disconnect
        rescue ::Interrupt
          raise $ERROR_INFO
        rescue ::Exception
        end

        begin
          print_status("Connecting to Nexpose instance at #{@host}:#{@port} with username #{@user}...")
          nsc = Nexpose::Connection.new(@host, @user, @pass, @port, nil, nil, @trust_cert)
          nsc.login
        rescue ::Nexpose::APIError => e
          print_error("Connection failed: #{e.reason}")
          return
        end

        @nsc = nsc
        nexpose_compatibility_check
        nsc
      end

      def cmd_nexpose_activity(*_args)
        return if !nexpose_verify

        scans = @nsc.scan_activity || []
        case scans.length
        when 0
          print_status('There are currently no active scan jobs on this Nexpose instance')
        when 1
          print_status('There is 1 active scan job on this Nexpose instance')
        else
          print_status("There are currently #{scans.length} active scan jobs on this Nexpose instance")
        end

        scans.each do |scan|
          print_status("    Scan ##{scan.scan_id} is running on Engine ##{scan.engine_id} against site ##{scan.site_id} since #{scan.start_time}")
        end
      end

      def cmd_nexpose_sites(*_args)
        return if !nexpose_verify

        sites = @nsc.list_sites || []
        case sites.length
        when 0
          print_status('There are currently no active sites on this Nexpose instance')
        end

        sites.each do |site|
          print_status("    Site ##{site.id} '#{site.name}' Risk Factor: #{site.risk_factor} Risk Score: #{site.risk_score}")
        end
      end

      def cmd_nexpose_site_devices(*args)
        return if !nexpose_verify

        site_id = args.shift
        if !site_id
          print_error('No site ID was specified')
          return
        end

        devices = @nsc.list_site_devices(site_id) || []
        case devices.length
        when 0
          print_status('There are currently no devices within this site')
        end

        devices.each do |device|
          print_status("    Host: #{device.address} ID: #{device.id} Risk Factor: #{device.risk_factor} Risk Score: #{device.risk_score}")
        end
      end

      def cmd_nexpose_report_templates(*_args)
        return if !nexpose_verify

        res = @nsc.list_report_templates || []

        res.each do |report|
          print_status("    Template: #{report.id} Name: '#{report.name}' Description: #{report.description}")
        end
      end

      def cmd_nexpose_command(*args)
        return if !nexpose_verify

        if args.empty?
          print_error('No command was specified')
          return
        end

        res = @nsc.console_command(args.join(' ')) || ''

        print_status('Command Output')
        print_line(res)
        print_line('')
      end

      def cmd_nexpose_sysinfo(*_args)
        return if !nexpose_verify

        res = @nsc.system_information

        print_status('System Information')
        res.each_pair do |k, v|
          print_status("    #{k}: #{v}")
        end
      end

      def nexpose_compatibility_check
        res = @nsc.console_command('ver')
        if res !~ /^(NSC|Console) Version ID:\s*4[89]0\s*$/m
          print_error('')
          print_error('Warning: This version of Nexpose has not been tested with Metasploit!')
          print_error('')
        end
      end

      def cmd_nexpose_site_import(*args)
        site_id = args.shift
        if !site_id
          print_error('No site ID was specified')
          return
        end

        msfid = Time.now.to_i

        report_formats = ['raw-xml-v2', 'ns-xml']
        report_format = report_formats.shift

        report = Nexpose::ReportConfig.build(@nsc, site_id, "Metasploit Export #{msfid}", 'pentest-audit', report_format, true)
        report.delivery = Nexpose::Delivery.new(true)

        begin
          report.format = report_format
          report.save(@nsc)
        rescue ::Exception => e
          report_format = report_formats.shift
          if report_format
            retry
          end
          raise e
        end

        print_status('Generating the export data file...')
        last_report = nil
        until last_report
          last_report = @nsc.last_report(report.id)
          select(nil, nil, nil, 1.0)
        end
        url = last_report.uri

        print_status('Downloading the export data...')
        data = @nsc.download(url)

        # Delete the temporary report ID
        @nsc.delete_report_config(report.id)

        print_status('Importing Nexpose data...')
        process_nexpose_data(report_format, data)
      end

      def cmd_nexpose_discover(*args)
        args << '-h' if args.empty?
        args << '-t'
        args << 'aggressive-discovery'
        cmd_nexpose_scan(*args)
      end

      def cmd_nexpose_exhaustive(*args)
        args << '-h' if args.empty?
        args << '-t'
        args << 'exhaustive-audit'
        cmd_nexpose_scan(*args)
      end

      def cmd_nexpose_dos(*args)
        args << '-h' if args.empty?
        args << '-t'
        args << 'dos-audit'
        cmd_nexpose_scan(*args)
      end

      def cmd_nexpose_scan(*args)
        opts = Rex::Parser::Arguments.new(
          '-h' => [ false, 'This help menu'],
          '-t' => [ true, 'The scan template to use (default:pentest-audit options:full-audit,exhaustive-audit,discovery,aggressive-discovery,dos-audit)'],
          '-c' => [ true, 'Specify credentials to use against these targets (format is type:user:pass'],
          '-n' => [ true, 'The maximum number of IPs to scan at a time (default is 32)'],
          '-s' => [ true, 'The directory to store the raw XML files from the Nexpose instance (optional)'],
          '-P' => [ false, 'Leave the scan data on the server when it completes (this counts against the maximum licensed IPs)'],
          '-v' => [ false, 'Display diagnostic information about the scanning process'],
          '-d' => [ false, 'Scan hosts based on the contents of the existing database'],
          '-I' => [ true, 'Only scan systems with an address within the specified range'],
          '-E' => [ true, 'Exclude hosts in the specified range from the scan']
        )

        opt_template = 'pentest-audit'
        opt_maxaddrs = 32
        opt_verbose = false
        opt_savexml = nil
        opt_preserve = false
        opt_rescandb = false
        opt_addrinc = nil
        opt_addrexc = nil
        opt_scanned = []
        opt_credentials = []

        opt_ranges = []

        opts.parse(args) do |opt, _idx, val|
          case opt
          when '-h'
            print_line('Usage: nexpose_scan [options] <Target IP Ranges>')
            print_line(opts.usage)
            return
          when '-t'
            opt_template = val
          when '-n'
            opt_maxaddrs = val.to_i
          when '-s'
            opt_savexml = val
          when '-c'
            if (val =~ /^([^:]+):([^:]+):(.+)/)
              type = Regexp.last_match(1)
              user = Regexp.last_match(2)
              pass = Regexp.last_match(3)
              msfid = Time.now.to_i
              newcreds = Nexpose::SiteCredentials.for_service("Metasploit Site Credential #{msfid}", nil, nil, nil, nil, type)
              newcreds.user_name = user
              newcreds.password = pass
              opt_credentials << newcreds
            else
              print_error("Unrecognized Nexpose scan credentials: #{val}")
              return
            end
          when '-v'
            opt_verbose = true
          when '-P'
            opt_preserve = true
          when '-d'
            opt_rescandb = true
          when '-I'
            opt_addrinc = OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(val)
          when '-E'
            opt_addrexc = OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(val)
          else
            opt_ranges << val
          end
        end

        return if !nexpose_verify

        # Include all database hosts as scan targets if specified
        if opt_rescandb
          print_status('Loading scan targets from the active database...') if opt_verbose
          framework.db.hosts.each do |host|
            next if host.state != ::Msf::HostState::Alive

            opt_ranges << host.address
          end
        end

        possible_files = opt_ranges # don't allow DOS by circular reference
        possible_files.each do |file|
          next unless ::File.readable? file

          print_status "Parsing ranges from #{file}"
          range_list = ::File.open(file, 'rb') { |f| f.read f.stat.size }
          range_list.each_line { |subrange| opt_ranges << subrange }
          opt_ranges.delete(file)
        end

        opt_ranges = opt_ranges.join(' ')

        if opt_ranges.strip.empty?
          print_line('Usage: nexpose_scan [options] <Target IP Ranges>')
          print_line(opts.usage)
          return
        end

        if opt_verbose
          print_status("Creating a new scan using template #{opt_template} and #{opt_maxaddrs} concurrent IPs against #{opt_ranges}")
        end

        range_inp = ::Msf::OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(opt_ranges)
        range = ::Rex::Socket::RangeWalker.new(range_inp)
        include_range = opt_addrinc ? ::Rex::Socket::RangeWalker.new(opt_addrinc) : nil
        exclude_range = opt_addrexc ? ::Rex::Socket::RangeWalker.new(opt_addrexc) : nil

        completed = 0
        total = range.num_ips
        count = 0

        print_status("Scanning #{total} addresses with template #{opt_template} in sets of #{opt_maxaddrs}")

        while (completed < total)
          count += 1
          queue = []

          while ((ip = range.next_ip) && (queue.length < opt_maxaddrs))

            if (exclude_range && exclude_range.include?(ip))
              print_status(" >> Skipping host #{ip} due to exclusion") if opt_verbose
              next
            end

            if (include_range && !include_range.include?(ip))
              print_status(" >> Skipping host #{ip} due to inclusion filter") if opt_verbose
              next
            end

            opt_scanned << ip
            queue << ip
          end

          break if queue.empty?

          print_status("Scanning #{queue[0]}-#{queue[-1]}...") if opt_verbose

          msfid = Time.now.to_i

          # Create a temporary site
          site = Nexpose::Site.new(nil, opt_template)
          site.name = "Metasploit-#{msfid}"
          site.description = 'Autocreated by the Metasploit Framework'
          site.included_addresses = queue
          site.site_credentials = opt_credentials
          site.save(@nsc)

          print_status(" >> Created temporary site ##{site.id}") if opt_verbose

          report_formats = ['raw-xml-v2', 'ns-xml']
          report_format = report_formats.shift

          report = Nexpose::ReportConfig.build(@nsc, site.id, site.name, opt_template, report_format, true)
          report.delivery = Nexpose::Delivery.new(true)

          begin
            report.format = report_format
            report.save(@nsc, true)
          rescue ::Exception => e
            report_format = report_formats.shift
            if report_format
              retry
            end
            raise e
          end

          print_status(" >> Created temporary report configuration ##{report.id}") if opt_verbose

          # Run the scan
          begin
            res = site.scan(@nsc)
          rescue Nexpose::APIError => e
            nexpose_error_message = e.message
            nexpose_error_message.gsub!(/NexposeAPI: Action failed: /, '')
            print_error nexpose_error_message.to_s
            return
          end

          sid = res.id

          print_status(" >> Scan has been launched with ID ##{sid}") if opt_verbose

          rep = true
          begin
            prev = nil
            while true
              info = @nsc.scan_statistics(sid)
              break if info.status != 'running'

              stat = "Found #{info.nodes.live} devices and #{info.nodes.dead} unresponsive"
              if (stat != prev) && opt_verbose
                print_status(" >> #{stat}")
              end
              prev = stat
              select(nil, nil, nil, 5.0)
            end
            print_status(" >> Scan has been completed with ID ##{sid}") if opt_verbose
          rescue ::Interrupt
            rep = false
            print_status(" >> Terminating scan ID ##{sid} due to console interrupt") if opt_verbose
            @nsc.stop_scan(sid)
            break
          end

          # Wait for the automatic report generation to complete
          if rep
            print_status(' >> Waiting on the report to generate...') if opt_verbose
            last_report = nil
            until last_report
              last_report = @nsc.last_report(report.id)
              select(nil, nil, nil, 1.0)
            end
            url = last_report.uri

            print_status(' >> Downloading the report data from Nexpose...') if opt_verbose
            data = @nsc.download(url)

            if opt_savexml
              ::FileUtils.mkdir_p(opt_savexml)
              path = ::File.join(opt_savexml, "nexpose-#{msfid}-#{count}.xml")
              print_status(" >> Saving scan data into #{path}") if opt_verbose
              ::File.open(path, 'wb') { |fd| fd.write(data) }
            end

            process_nexpose_data(report_format, data)
          end

          next if opt_preserve

          # Make sure the scan has finished clean up before attempting to delete the site
          loop do
            info = @nsc.scan_statistics(sid)
            break if info.status == 'stopped' || info.status == 'finished'

            select(nil, nil, nil, 5.0)
          end
          print_status(' >> Deleting the temporary site and report...') if opt_verbose
          begin
            @nsc.delete_site(site.id)
          rescue ::Nexpose::APIError => e
            print_status(" >> Deletion of temporary site and report failed: #{e.inspect}")
          end
        end

        print_status("Completed the scan of #{total} addresses")
      end

      def cmd_nexpose_disconnect(*_args)
        @nsc.logout if @nsc
        @nsc = nil
      end

      def process_nexpose_data(fmt, data)
        case fmt
        when 'raw-xml-v2'
          framework.db.import({ data: data })
        when 'ns-xml'
          framework.db.import({ data: data })
        else
          print_error("Unsupported Nexpose data format: #{fmt}")
        end
      end

      #
      # Nexpose vuln lookup
      #
      def nexpose_vuln_lookup(doc, vid, refs, host, serv = nil)
        doc.elements.each("/NexposeReport/VulnerabilityDefinitions/vulnerability[@id = '#{vid}']]") do |vulndef|
          title = vulndef.attributes['title']
          # pci_severity = vulndef.attributes['pciSeverity']
          # cvss_score = vulndef.attributes['cvssScore']
          # cvss_vector = vulndef.attributes['cvssVector']

          vulndef.elements['references'].elements.each('reference') do |ref|
            if ref.attributes['source'] == 'BID'
              refs['BID-' + ref.text] = true
            elsif ref.attributes['source'] == 'CVE'
              # ref.text is CVE-$ID
              refs[ref.text] = true
            elsif ref.attributes['source'] == 'MS'
              refs['MSB-MS-' + ref.text] = true
            end
          end

          refs['NEXPOSE-' + vid.downcase] = true

          vuln = framework.db.find_or_create_vuln(
            host: host,
            service: serv,
            name: 'NEXPOSE-' + vid.downcase,
            data: title
          )

          rids = []
          refs.each_key do |r|
            rids << framework.db.find_or_create_ref(name: r)
          end

          vuln.refs << (rids - vuln.refs)
        end
      end

    end

    #
    # Plugin initialization
    #

    def initialize(framework, opts)
      super

      add_console_dispatcher(NexposeCommandDispatcher)
      banner = ['0a205f5f5f5f202020202020202020202020205f20202020205f205f5f5f5f5f2020205f2020205f20202020205f5f20205f5f2020202020202020202020202020202020202020200a7c20205f205c205f5f205f205f205f5f20285f29205f5f7c207c5f5f5f20207c207c205c207c207c205f5f5f5c205c2f202f5f205f5f2020205f5f5f20205f5f5f20205f5f5f200a7c207c5f29202f205f60207c20275f205c7c207c2f205f60207c20202f202f20207c20205c7c207c2f205f205c5c20202f7c20275f205c202f205f205c2f205f5f7c2f205f205c0a7c20205f203c20285f7c207c207c5f29207c207c20285f7c207c202f202f2020207c207c5c20207c20205f5f2f2f20205c7c207c5f29207c20285f29205c5f5f205c20205f5f2f0a7c5f7c205c5f5c5f5f2c5f7c202e5f5f2f7c5f7c5c5f5f2c5f7c2f5f2f202020207c5f7c205c5f7c5c5f5f5f2f5f2f5c5f5c202e5f5f2f205c5f5f5f2f7c5f5f5f2f5c5f5f5f7c0a20202020202020202020207c5f7c20202020202020202020202020202020202020202020202020202020202020202020207c5f7c202020202020202020202020202020202020200a0a0a'].pack('H*')

      # Do not use this UTF-8 encoded high-ascii art for non-UTF-8 or windows consoles
      lang = Rex::Compat.getenv('LANG')
      if (lang && lang =~ (/UTF-8/))
        # Cygwin/Windows should not be reporting UTF-8 either...
        # (! (Rex::Compat.is_windows or Rex::Compat.is_cygwin))
        banner = ['202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a20e29684e29684e29684202020e29684e29684202020202020202020202020e29684e29684e296842020e29684e29684e2968420202020202020202020202020202020202020202020202020202020202020202020202020202020200a20e29688e29688e29688202020e29688e2968820202020202020202020202020e29688e2968820e29684e29688e296882020202020202020202020202020202020202020202020202020202020202020202020202020202020200a20e29688e29688e29680e296882020e29688e29688202020e29684e29688e29688e29688e29688e296842020202020e29688e29688e29688e2968820202020e29688e29688e29684e29688e29688e29688e2968420202020e29684e29688e29688e29688e29688e29684202020e29684e29684e29688e29688e29688e29688e29688e29684202020e29684e29688e29688e29688e29688e2968420200a20e29688e2968820e29688e2968820e29688e296882020e29688e29688e29684e29684e29684e29684e29688e296882020202020e29688e296882020202020e29688e29688e296802020e29680e29688e296882020e29688e29688e296802020e29680e29688e296882020e29688e29688e29684e29684e29684e2968420e296802020e29688e29688e29684e29684e29684e29684e29688e29688200a20e29688e296882020e29688e29684e29688e296882020e29688e29688e29680e29680e29680e29680e29680e2968020202020e29688e29688e29688e2968820202020e29688e2968820202020e29688e296882020e29688e2968820202020e29688e29688202020e29680e29680e29680e29680e29688e29688e296842020e29688e29688e29680e29680e29680e29680e29680e29680200a20e29688e29688202020e29688e29688e296882020e29680e29688e29688e29684e29684e29684e29684e29688202020e29688e296882020e29688e29688202020e29688e29688e29688e29684e29684e29688e29688e296802020e29680e29688e29688e29684e29684e29688e29688e296802020e29688e29684e29684e29684e29684e29684e29688e296882020e29680e29688e29688e29684e29684e29684e29684e29688200a20e29680e29680202020e29680e29680e2968020202020e29680e29680e29680e29680e29680202020e29680e29680e296802020e29680e29680e296802020e29688e2968820e29680e29680e29680202020202020e29680e29680e29680e296802020202020e29680e29680e29680e29680e29680e296802020202020e29680e29680e29680e29680e2968020200a20202020202020202020202020202020202020202020202020202020202020e29688e29688202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a'].pack('H*')
      end
      print(banner)
      print_status('Nexpose integration has been activated')
    end

    def cleanup
      remove_console_dispatcher('Nexpose')
    end

    def name
      'nexpose'
    end

    def desc
      'Integrates with the Rapid7 Nexpose vulnerability management product'
    end
  end
end

module Nexpose
  class IPRange
    def to_json(*_args)
      if @to.present?
        "#{@from} - #{@to}".to_json
      else
        @from.to_json
      end
    end
  end
end
