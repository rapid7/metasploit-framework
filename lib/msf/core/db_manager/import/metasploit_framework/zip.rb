module Msf::DBManager::Import::MetasploitFramework::Zip
  # Imports loot, tasks, and reports from an MSF ZIP report.
  # XXX: This function is stupidly long. It needs to be refactored.
  def import_msf_collateral(args={}, &block)
    data = ::File.open(args[:filename], "rb") {|f| f.read(f.stat.size)}
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    basedir = args[:basedir] || args['basedir'] || ::File.join(Msf::Config.data_directory, "msf")

    allow_yaml = false
    btag = nil

    doc = Nokogiri::XML::Reader.from_memory(data)
    case doc.first.name
    when "MetasploitExpressV1"
      m_ver = 1
      allow_yaml = true
      btag = "MetasploitExpressV1"
    when "MetasploitExpressV2"
      m_ver = 2
      allow_yaml = true
      btag = "MetasploitExpressV2"
    when "MetasploitExpressV3"
      m_ver = 3
      btag = "MetasploitExpressV3"
    when "MetasploitExpressV4"
      m_ver = 4
      btag = "MetasploitExpressV4"
    when "MetasploitV4"
      m_ver = 4
      btag = "MetasploitV4"
    else
      m_ver = nil
    end
    unless m_ver and btag
      raise Msf::DBImportError.new("Unsupported Metasploit XML document format")
    end

    host_info = {}

    doc.each do |node|
      if ['host', 'loot', 'task', 'report'].include?(node.name)
        unless node.inner_xml.empty?
          send("parse_zip_#{node.name}", Nokogiri::XML(node.outer_xml).at("./#{node.name}"), wspace, bl, allow_yaml, btag, args, basedir, host_info, &block)
        end
      end
    end
  end

  # Parses host Nokogiri::XML::Element
  def parse_zip_host(host, wspace, bl, allow_yaml, btag, args, basedir, host_info, &block)
    host_info[host.at("id").text.to_s.strip] = nils_for_nulls(host.at("address").text.to_s.strip) unless host.at('address').nil?
  end

  # Parses loot Nokogiri::XML::Element
  def parse_zip_loot(loot, wspace, bl, allow_yaml, btag, args, basedir, host_info, &block)
    return 0 if bl.include? host_info[loot.at("host-id").text.to_s.strip]
    loot_info              = {}
    loot_info[:host]       = host_info[loot.at("host-id").text.to_s.strip]
    loot_info[:workspace]  = args[:workspace]
    loot_info[:ctype]      = nils_for_nulls(loot.at("content-type").text.to_s.strip)
    loot_info[:info]       = nils_for_nulls(unserialize_object(loot.at("info"), allow_yaml))
    loot_info[:ltype]      = nils_for_nulls(loot.at("ltype").text.to_s.strip)
    loot_info[:name]       = nils_for_nulls(loot.at("name").text.to_s.strip)
    loot_info[:created_at] = nils_for_nulls(loot.at("created-at").text.to_s.strip)
    loot_info[:updated_at] = nils_for_nulls(loot.at("updated-at").text.to_s.strip)
    loot_info[:name]       = nils_for_nulls(loot.at("name").text.to_s.strip)
    loot_info[:orig_path]  = nils_for_nulls(loot.at("path").text.to_s.strip)
    loot_info[:task]       = args[:task]
    tmp = args[:ifd][:zip_tmp]
    loot_info[:orig_path].gsub!(/^\./,tmp) if loot_info[:orig_path]
    if !loot.at("service-id").text.to_s.strip.empty?
      unless loot.at("service-id").text.to_s.strip == "NULL"
        loot_info[:service] = loot.at("service-id").text.to_s.strip
      end
    end

    # Only report loot if we actually have it.
    # TODO: Copypasta. Separate this out.
    if ::File.exist? loot_info[:orig_path]
      loot_dir = ::File.join(basedir,"loot")
      loot_file = ::File.split(loot_info[:orig_path]).last
      if ::File.exist? loot_dir
        unless (::File.directory?(loot_dir) && ::File.writable?(loot_dir))
          raise Msf::DBImportError.new("Could not move files to #{loot_dir}")
        end
      else
        ::FileUtils.mkdir_p(loot_dir)
      end
      new_loot = ::File.join(loot_dir,loot_file)
      loot_info[:path] = new_loot
      if ::File.exist?(new_loot)
        ::File.unlink new_loot # Delete it, and don't report it.
      else
        report_loot(loot_info) # It's new, so report it.
      end
      ::FileUtils.copy(loot_info[:orig_path], new_loot)
      yield(:msf_loot, new_loot) if block
    end
  end

  # Parses task Nokogiri::XML::Element
  def parse_zip_task(task, wspace, bl, allow_yaml, btag, args, basedir, host_info, &block)
    task_info = {}
    task_info[:workspace] = args[:workspace]
    # Should user be imported (original) or declared (the importing user)?
    task_info[:user] = nils_for_nulls(task.at("created-by").text.to_s.strip)
    task_info[:desc] = nils_for_nulls(task.at("description").text.to_s.strip)
    task_info[:info] = nils_for_nulls(unserialize_object(task.at("info"), allow_yaml))
    task_info[:mod] = nils_for_nulls(task.at("module").text.to_s.strip)
    task_info[:options] = nils_for_nulls(task.at("options").text.to_s.strip)
    task_info[:prog] = nils_for_nulls(task.at("progress").text.to_s.strip).to_i
    task_info[:created_at] = nils_for_nulls(task.at("created-at").text.to_s.strip)
    task_info[:updated_at] = nils_for_nulls(task.at("updated-at").text.to_s.strip)
    if !task.at("completed-at").text.to_s.empty?
      task_info[:completed_at] = nils_for_nulls(task.at("completed-at").text.to_s.strip)
    end
    if !task.at("error").text.to_s.empty?
      task_info[:error] = nils_for_nulls(task.at("error").text.to_s.strip)
    end
    if !task.at("result").text.to_s.empty?
      task_info[:result] = nils_for_nulls(task.at("result").text.to_s.strip)
    end
    task_info[:orig_path] = nils_for_nulls(task.at("path").text.to_s.strip)
    tmp = args[:ifd][:zip_tmp]
    task_info[:orig_path].gsub!(/^\./,tmp) if task_info[:orig_path]

    # Only report a task if we actually have it.
    # TODO: Copypasta. Separate this out.
    if ::File.exist? task_info[:orig_path]
      tasks_dir = ::File.join(basedir,"tasks")
      task_file = ::File.split(task_info[:orig_path]).last
      if ::File.exist? tasks_dir
        unless (::File.directory?(tasks_dir) && ::File.writable?(tasks_dir))
          raise Msf::DBImportError.new("Could not move files to #{tasks_dir}")
        end
      else
        ::FileUtils.mkdir_p(tasks_dir)
      end
      new_task = ::File.join(tasks_dir,task_file)
      task_info[:path] = new_task
      if ::File.exist?(new_task)
        ::File.unlink new_task # Delete it, and don't report it.
      else
        report_task(task_info) # It's new, so report it.
      end
      ::FileUtils.copy(task_info[:orig_path], new_task)
      yield(:msf_task, new_task) if block
    end
  end

  # Parses report Nokogiri::XML::Element
  def parse_zip_report(report, wspace, bl, allow_yaml, btag, args, basedir, host_info, &block)
    import_report(report, args, basedir)
  end

  # Import a Metasploit Express ZIP file. Note that this requires
  # a fair bit of filesystem manipulation, and is very much tied
  # up with the Metasploit Express ZIP file format export (for
  # obvious reasons). In the event directories exist, they will
  # be reused. If target files exist, they will be overwritten.
  #
  # XXX: Refactor so it's not quite as sanity-blasting.
  def import_msf_zip(args={}, &block)
    data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    new_tmp = ::File.join(Dir::tmpdir,"msf","imp_#{Rex::Text::rand_text_alphanumeric(4)}",@import_filedata[:zip_basename])
    if ::File.exist? new_tmp
      unless (::File.directory?(new_tmp) && ::File.writable?(new_tmp))
        raise Msf::DBImportError.new("Could not extract zip file to #{new_tmp}")
      end
    else
      FileUtils.mkdir_p(new_tmp)
    end
    @import_filedata[:zip_tmp] = new_tmp

    # Grab the list of unique basedirs over all entries.
    @import_filedata[:zip_tmp_subdirs] = @import_filedata[:zip_entry_names].map {|x| ::File.split(x)}.map {|x| x[0]}.uniq.reject {|x| x == "."}

    # mkdir all of the base directories we just pulled out, if they don't
    # already exist
    @import_filedata[:zip_tmp_subdirs].each {|sub|
      tmp_subdirs = ::File.join(@import_filedata[:zip_tmp],sub)
      if File.exist? tmp_subdirs
        unless (::File.directory?(tmp_subdirs) && File.writable?(tmp_subdirs))
          # if it exists but we can't write to it, give up
          raise Msf::DBImportError.new("Could not extract zip file to #{tmp_subdirs}")
        end
      else
        ::FileUtils.mkdir(tmp_subdirs)
      end
    }

    data.entries.each do |e|
      # normalize entry name to an absolute path
      target = File.expand_path(File.join(@import_filedata[:zip_tmp], e.name), '/').to_s

      # skip if the target would be extracted outside of the zip
      # tmp dir to mitigate any directory traversal attacks
      next unless is_child_of?(@import_filedata[:zip_tmp], target)

      e.extract(target)

      if target =~ /\.xml\z/
        target_data = ::File.open(target, "rb") {|f| f.read 1024}
        if import_filetype_detect(target_data) == :msf_xml
          @import_filedata[:zip_extracted_xml] = target
        end
      end
    end

    # Import any creds if there are some in the import file
    Dir.entries(@import_filedata[:zip_tmp]).each do |entry|
      if entry =~ /^.*#{Regexp.quote(Metasploit::Credential::Exporter::Core::CREDS_DUMP_FILE_IDENTIFIER)}.*/
        manifest_file_path = File.join(@import_filedata[:zip_tmp], entry, Metasploit::Credential::Importer::Zip::MANIFEST_FILE_NAME)
        if File.exist? manifest_file_path
          import_msf_cred_dump(manifest_file_path, wspace)
        end
      end
    end

    # This will kick the newly-extracted XML file through
    # the import_file process all over again.
    if @import_filedata[:zip_extracted_xml]
      new_args = args.dup
      new_args[:filename] = @import_filedata[:zip_extracted_xml]
      new_args[:data] = nil
      new_args[:ifd] = @import_filedata.dup
      if block
        import_file(new_args, &block)
      else
        import_file(new_args)
      end
    end

    # Kick down to all the MSFX ZIP specific items
    if block
      import_msf_collateral(new_args, &block)
    else
      import_msf_collateral(new_args)
    end
  end

  def is_child_of?(target_dir, target)
    target.downcase.start_with?(target_dir.downcase)
  end
end
