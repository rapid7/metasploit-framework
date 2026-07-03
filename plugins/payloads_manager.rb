require 'json'
require 'fileutils'
require 'digest'
require 'net/http'
require 'uri'
require 'time'
require 'securerandom'

module Msf
  class Plugin::PayloadsManager < Msf::Plugin
    def initialize(framework, opts)
      super
      add_console_dispatcher(PayloadsManagerCommandDispatcher)
      print_status("PayloadsManager plugin loaded.")
    end

    def cleanup
      remove_console_dispatcher('PayloadsManager')
    end

    def name
      "payloads_manager"
    end

    def desc
      "Manages payloads for exploitation"
    end

    class PayloadsManagerCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      PAYLOADS_DIR = File.join(Msf::Config.config_directory, 'payloads')
      DATABASE_FILE = File.join(PAYLOADS_DIR, 'payloads.json')
      MSF_METERPRETER_DIR = File.join(Msf::Config.data_directory, 'meterpreter')
      MAX_FETCH_SIZE = 100 * 1024 * 1024

      def initialize(driver)
        super
        @driver = driver
        setup_directories
        load_database
      end

      def name
        "PayloadsManager"
      end

      def commands
        {
          'payloads_manager' => 'Manage payloads: list | add <path> [name] | fetch <url> [name] | select <id> | unselect <id> | remove <id> | help'
        }
      end

      def cmd_payloads_manager(*args)
        subcommand = args.shift

        case subcommand
        when 'list'
          handle_list
        when 'add'
          handle_add(*args)
        when 'fetch'
          handle_fetch(*args)
        when 'select'
          handle_select(*args)
        when 'unselect'
          handle_unselect(*args)
        when 'remove'
          handle_remove(*args)
        when 'help', nil
          handle_help
        else
          print_error("Unknown subcommand: #{subcommand}")
          handle_help
        end
      end

      private

      def handle_list
        if @database.empty?
          print_line("No payloads in archive.")
          return
        end

        tbl = Rex::Text::Table.new(
          'Header'  => 'Payloads',
          'Indent'  => 1,
          'Columns' => ['ID', 'Name', 'Description', 'Tags', 'Added At', 'Last Selected At', 'Status'],
          'SortIndex' => 6,
          'ColProps' =>
          {
            'Status' => {
              'Stylers' => [::Msf::Ui::Console::TablePrint::CustomColorStyler.new('Active' => '%grn', 'Inactive' => '%red')]
            }
          }
        )

        difference_in_seconds = lambda do |time_str|
          now = Time.now
          return 'Never' if time_str.nil?
          begin
            time = Time.parse(time_str)
          rescue ArgumentError, TypeError
            return 'Invalid timestamp'
          end
          diff = now - time
          if diff < 60
            "#{diff.to_i} seconds ago"
          elsif diff < 3600
            "#{(diff / 60).to_i} minutes ago"
          elsif diff < 86400
            "#{(diff / 3600).to_i} hours ago"
          else
            "#{(diff / 86400).to_i} days ago"
          end
        end

        @database.each do |_id, payload|
          added = difference_in_seconds.call(payload['added_at'])
          last_selected = difference_in_seconds.call(payload['last_selected_at'])
          tbl << [
            _id.split('_').last,
            payload['name'].to_s,
            payload['description'].to_s,
            Array(payload['tags']).join(', '),
            added,
            last_selected,
            payload['active'] ? 'Active' : 'Inactive'
          ]
        end


        print_line(tbl.to_s)
      end

      def handle_add(*args)
        if args.empty?
          print_error("Usage: payloads_manager add <path_to_payload> [name] [--description <desc>] [--tags <t1,t2,...>]")
          return
        end

        parsed = parse_subcommand_args(args)
        if parsed[:error]
          print_error(parsed[:error])
          print_error("Usage: payloads_manager add <path_to_payload> [name] [--description <desc>] [--tags <t1,t2,...>]")
          return
        end
        positional = parsed[:positional]
        description = parsed[:description]
        tags = parsed[:tags]

        if positional.empty?
          print_error("Usage: payloads_manager add <path_to_payload> [name] [--description <desc>] [--tags <t1,t2,...>]")
          return
        end

        source_path = File.expand_path(positional[0])
        unless File.exist?(source_path)
          print_error("File not found: #{source_path}")
          return
        end

        name = positional[1] || File.basename(source_path)
        id = generate_id(name)
        sha256 = Digest::SHA256.file(source_path).hexdigest
        dest_path = File.join(PAYLOADS_DIR, "#{id}_#{File.basename(source_path)}")

        FileUtils.cp(source_path, dest_path)

        @database[id] = {
          'name' => name,
          'path' => dest_path,
          'sha256' => sha256,
          'active' => false,
          'added_at' => Time.now.to_s,
          'last_selected_at' => nil,
          'description' => description.to_s,
          'tags' => tags
        }

        save_database
        print_good("Payload added: #{name} (ID: #{id})")
        print_status("  Description: #{description}") if description && !description.empty?
        print_status("  Tags: #{tags.join(', ')}") unless tags.empty?
      end

      def handle_fetch(*args)
        if args.empty?
          print_error("Usage: payloads_manager fetch <url> [name] [--description <desc>] [--tags <t1,t2,...>]")
          return
        end

        parsed = parse_subcommand_args(args)
        if parsed[:error]
          print_error(parsed[:error])
          print_error("Usage: payloads_manager fetch <url> [name] [--description <desc>] [--tags <t1,t2,...>]")
          return
        end
        positional = parsed[:positional]
        description = parsed[:description]
        tags = parsed[:tags]

        if positional.empty?
          print_error("Usage: payloads_manager fetch <url> [name] [--description <desc>] [--tags <t1,t2,...>]")
          return
        end

        url = positional[0]
        uri = URI.parse(url)
        unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
          print_error("Invalid URL (must be http or https): #{url}")
          return
        end

        print_status("Fetching payload from #{url}...")

        begin
          fetched_payload = fetch_to_archive_with_redirects(uri, positional[1])
        rescue StandardError => e
          print_error("Failed to fetch payload: #{e.message}")
          return
        end

        @database[fetched_payload[:id]] = {
          'name' => fetched_payload[:name],
          'path' => fetched_payload[:dest_path],
          'sha256' => fetched_payload[:sha256],
          'active' => false,
          'added_at' => Time.now.to_s,
          'last_selected_at' => nil,
          'source_url' => url,
          'description' => description.to_s,
          'tags' => tags
        }

        save_database
        print_good("Payload fetched and added: #{fetched_payload[:name]} (ID: #{fetched_payload[:id]})")
        print_status("  SHA256: #{fetched_payload[:sha256]}")
        print_status("  Size: #{fetched_payload[:size]} bytes")
        print_status("  Description: #{description}") if description && !description.empty?
        print_status("  Tags: #{tags.join(', ')}") unless tags.empty?
      end

      def parse_subcommand_args(args)
        description = nil
        tags = []
        positional = []
        error = nil

        i = 0
        while i < args.length
          case args[i]
          when '--description', '-d'
            i += 1
            unless args[i]
              error = "Missing value for #{args[i - 1]}"
              break
            end
            description = args[i]
          when '--tags', '-t'
            i += 1
            unless args[i]
              error = "Missing value for #{args[i - 1]}"
              break
            end
            tags = args[i].to_s.split(',').map(&:strip).reject(&:empty?) if args[i]
          else
            positional << args[i]
          end
          i += 1
        end

        {
          positional: positional,
          description: description,
          tags: tags,
          error: error
        }
      end

      def handle_select(*args)
        if args.empty?
          print_error("Usage: payloads_manager select <payload_id>")
          return
        end

        id = args[0]
        unless @database.key?(id)
          print_error("Payload not found: #{id}")
          return
        end

        payload = @database[id]
        target_link = meterpreter_target_link(payload['name'], context: "select payload '#{id}'")
        return unless target_link
        source_path = archived_payload_source_path(payload['path'], context: "select payload '#{id}'")
        return unless source_path

        # Only deactivate payloads that target the same filename (would conflict)
        @database.each do |other_id, v|
          next unless v['active']
          other_link = meterpreter_target_link(v['name'], context: "check active payload '#{other_id}'")
          next unless other_link
          if other_link == target_link
            FileUtils.rm(other_link) if File.symlink?(other_link)
            v['active'] = false
          end
        end

        # Refuse to overwrite an existing non-symlink file at the target path
        if File.exist?(target_link) && !File.symlink?(target_link)
          print_error("Cannot select payload '#{payload['name']}'. A non-symlink file already exists at #{target_link}. Please move or remove it and try again.")
          return
        end

        begin
          FileUtils.rm(target_link) if File.symlink?(target_link)
          FileUtils.ln_s(source_path, target_link)
        rescue SystemCallError => e
          print_error("Failed to activate payload '#{payload['name']}' at #{target_link}: #{e.class}: #{e.message}")
          return
        end
        @database[id]['active'] = true
        @database[id]['last_selected_at'] = Time.now.to_s
        save_database

        active_count = @database.count { |_, v| v['active'] }
        print_good("Payload '#{payload['name']}' selected and symlinked to #{target_link}")
        print_status("  #{active_count} payload(s) currently active") if active_count > 1
      end

      def handle_unselect(*args)
        if args.empty?
          print_error("Usage: payloads_manager unselect <payload_id>")
          return
        end

        id = args[0]
        unless @database.key?(id)
          print_error("Payload not found: #{id}")
          return
        end

        payload = @database[id]
        unless payload['active']
          print_error("Payload '#{payload['name']}' is not currently active.")
          return
        end

        target_link = meterpreter_target_link(payload['name'], context: "unselect payload '#{id}'")
        return unless target_link
        FileUtils.rm(target_link) if File.symlink?(target_link)
        payload['active'] = false
        save_database

        print_good("Payload '#{payload['name']}' unselected and symlink removed.")
      end

      def handle_remove(*args)
        if args.empty?
          print_error("Usage: payloads_manager remove <payload_id>")
          return
        end

        id = args[0]
        unless @database.key?(id)
          print_error("Payload not found: #{id}")
          return
        end

        payload = @database[id]
        if payload['active']
          target_link = meterpreter_target_link(payload['name'], context: "remove payload '#{id}'")
          FileUtils.rm(target_link) if target_link && File.symlink?(target_link)
          payload['active'] = false
        end

        payload_path = archived_payload_source_path(payload['path'], context: "remove payload '#{id}'", require_exists: false)
        if payload_path && File.exist?(payload_path)
          begin
            File.delete(payload_path)
          rescue SystemCallError => e
            print_error("Failed to remove archived payload file '#{payload_path}': #{e.class}: #{e.message}")
            return
          end
        elsif payload_path
          print_status("Archived payload file not found; removing database entry only: #{payload_path}")
        else
          print_error("Skipping payload file deletion for '#{payload['name']}' due to invalid stored path; removing database entry only.")
        end

        @database.delete(id)
        save_database

        print_good("Payload removed: #{payload['name']}")
      end

      def handle_help
        print_status("PayloadsManager Help")
        print_status("=" * 50)
        print_status("  payloads_manager list")
        print_status("  payloads_manager add <path_to_payload> [name] [--description <desc>] [--tags <t1,t2,...>]")
        print_status("  payloads_manager fetch <url> [name] [--description <desc>] [--tags <t1,t2,...>]")
        print_status("  payloads_manager select <payload_id>")
        print_status("  payloads_manager unselect <payload_id>")
        print_status("  payloads_manager remove <payload_id>")
        print_status("  payloads_manager help")
      end

      def setup_directories
        FileUtils.mkdir_p(PAYLOADS_DIR) unless Dir.exist?(PAYLOADS_DIR)
        FileUtils.mkdir_p(MSF_METERPRETER_DIR) unless Dir.exist?(MSF_METERPRETER_DIR)
      end

      def load_database
        if File.exist?(DATABASE_FILE)
          begin
            contents = File.read(DATABASE_FILE)
            if contents.strip.empty?
              @database = {}
            else
              @database = JSON.parse(contents)
            end
          rescue JSON::ParserError => e
            backup_path = "#{DATABASE_FILE}.corrupted-#{Time.now.to_i}"
            begin
              FileUtils.mv(DATABASE_FILE, backup_path)
              print_error("Failed to parse payloads database; backing up corrupted file to #{backup_path}: #{e.message}")
            rescue StandardError
              print_error("Failed to parse payloads database and could not back up corrupted file: #{e.message}")
            end
            @database = {}
          end
        else
          @database = {}
        end
      end

      def save_database
        File.write(DATABASE_FILE, JSON.pretty_generate(@database))
      end

      def generate_id(_name)
        loop do
          id = SecureRandom.hex(8)
          return id unless @database.key?(id)
        end
      end

      def meterpreter_target_link(payload_name, context: nil)
        base_name = File.basename(payload_name.to_s.tr('\\', '/'))
        if base_name.empty? || base_name == '.' || base_name == '..'
          print_error("Invalid payload name '#{payload_name}'#{context ? " while trying to #{context}" : ''}.")
          return nil
        end

        meterpreter_dir = File.expand_path(MSF_METERPRETER_DIR)
        target_link = File.expand_path(File.join(meterpreter_dir, base_name))
        unless target_link.start_with?(meterpreter_dir + File::SEPARATOR)
          print_error("Refusing to use target path outside meterpreter directory: #{target_link}")
          return nil
        end

        target_link
      end

      def archived_payload_source_path(payload_path, context: nil, require_exists: true)
        source_path = File.expand_path(payload_path.to_s)
        payloads_dir = File.expand_path(PAYLOADS_DIR)

        unless source_path.start_with?(payloads_dir + File::SEPARATOR)
          print_error("Refusing to use payload path outside managed payloads directory#{context ? " while trying to #{context}" : ''}: #{source_path}")
          return nil
        end

        if require_exists && !File.exist?(source_path)
          print_error("Payload file is missing#{context ? " while trying to #{context}" : ''}: #{source_path}")
          return nil
        end

        source_path
      end

      def fetch_to_archive_with_redirects(uri, requested_name = nil, limit = 5, max_size = MAX_FETCH_SIZE)
        raise "Too many redirects" if limit == 0

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == 'https')
        http.open_timeout = 10
        http.read_timeout = 30

        request = Net::HTTP::Get.new(uri)
        http.request(request) do |response|
          case response
          when Net::HTTPRedirection
            location_header = response['location']
            raise 'Redirect response missing Location header' if location_header.to_s.strip.empty?

            location = URI.parse(location_header)
            location = uri + location unless location.is_a?(URI::HTTP) || location.is_a?(URI::HTTPS)
            print_status("  Following redirect to #{location}")
            return fetch_to_archive_with_redirects(location, requested_name, limit - 1, max_size)
          when Net::HTTPSuccess
            filename = derive_filename(uri, response)
            name = requested_name || filename
            id = generate_id(name)
            dest_path = File.join(PAYLOADS_DIR, "#{id}_#{filename}")
            bytes_written = 0

            begin
              File.open(dest_path, 'wb') do |file|
                response.read_body do |chunk|
                  bytes_written += chunk.bytesize
                  raise "Downloaded payload exceeds maximum allowed size of #{max_size} bytes" if bytes_written > max_size

                  file.write(chunk)
                end
              end
            rescue StandardError
              File.delete(dest_path) if File.exist?(dest_path)
              raise
            end

            return {
              id: id,
              name: name,
              dest_path: dest_path,
              sha256: Digest::SHA256.file(dest_path).hexdigest,
              size: bytes_written
            }
          else
            raise "HTTP request failed: #{response.code} #{response.message}"
          end
        end
      end

      def derive_filename(uri, response)
        filename = nil

        # Try Content-Disposition header first
        if (cd = response['content-disposition'])
          match = cd.match(/filename="?([^";]+)"?/i)
          filename = match[1].strip if match
        end

        if filename.nil? || filename.empty?
          # Fall back to the last segment of the URL path
          path_basename = File.basename(uri.path)
          filename = path_basename unless path_basename.empty? || path_basename == '/'
        end

        filename = 'fetched_payload' if filename.nil? || filename.empty?

        sanitize_filename(filename)
      end

      def sanitize_filename(filename)
        # Normalize separators first, then keep only a safe basename.
        sanitized = File.basename(filename.to_s.tr('\\', '/'))
        sanitized = sanitized.gsub(/[\x00-\x1f]/, '')
        sanitized = sanitized.gsub(/[^0-9A-Za-z._-]/, '_')

        return 'fetched_payload' if sanitized.empty? || sanitized == '.' || sanitized == '..'

        sanitized
      end
    end
  end
end
