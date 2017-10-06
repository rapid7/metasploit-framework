module LootServlet

  def self.api_path
    '/api/1/msf/loot'
  end

  def self.registered(app)
    app.get LootServlet.api_path, &get_loot
    app.post LootServlet.api_path, &report_loot
  end

  #######
  private
  #######

  def self.get_loot
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().loots(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_loot
    lambda {

      job = lambda { |opts|
        # This regex does a best attempt to determine if opts[:data] is valid Base64
        # See https://stackoverflow.com/questions/8571501/how-to-check-whether-the-string-is-base64-encoded-or-not
        if opts[:data] =~ /^([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)$/
          opts[:data] = Base64.urlsafe_decode64(opts[:data]) if opts[:data]
        end

        # This code is all for writing out the file locally.
        # It is copied from lib/msf/core/auxiliary/report.rb
        # We shouldn't duplicate it so a better method should be used
        if ! ::File.directory?(Msf::Config.loot_directory)
          FileUtils.mkdir_p(Msf::Config.loot_directory)
        end

        ext = 'bin'
        if opts[:name]
          parts = opts[:name].to_s.split('.')
          if parts.length > 1 and parts[-1].length < 4
            ext = parts[-1]
          end
        end

        case opts[:content_type]
          when /^text\/[\w\.]+$/
            ext = "txt"
        end
        # This method is available even if there is no database, don't bother checking
        host = Msf::Util::Host.normalize_host(opts[:host])

        ws = (opts[:workspace] ? opts[:workspace] : 'default')
        name =
            Time.now.strftime("%Y%m%d%H%M%S") + "_" + ws + "_" +
                (host || 'unknown') + '_' + opts[:type][0,16] + '_' +
                Rex::Text.rand_text_numeric(6) + '.' + ext

        name.gsub!(/[^a-z0-9\.\_]+/i, '')

        path = File.join(Msf::Config.loot_directory, name)
        full_path = ::File.expand_path(path)
        File.open(full_path, "wb") do |fd|
          fd.write(opts[:data])
        end

        get_db().report_loot(opts)
      }
      exec_report_job(request, &job)
    }
  end
end