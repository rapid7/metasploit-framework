module Msf::DBManager::Import::MetasploitFramework::Zip
  # Import a Metasploit Express ZIP file. Note that this requires
  # a fair bit of filesystem manipulation, and is very much tied
  # up with the Metasploit Express ZIP file format export (for
  # obvious reasons). In the event directories exist, they will
  # be reused. If target files exist, they will be overwritten.
  #
  # XXX: Refactor so it's not quite as sanity-blasting.
  def import_msf_zip(args={}, &block)
    data = args[:data]
    wpsace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    new_tmp = ::File.join(Dir::tmpdir,"msf","imp_#{Rex::Text::rand_text_alphanumeric(4)}",@import_filedata[:zip_basename])
    if ::File.exists? new_tmp
      unless (::File.directory?(new_tmp) && ::File.writable?(new_tmp))
        raise DBImportError.new("Could not extract zip file to #{new_tmp}")
      end
    else
      FileUtils.mkdir_p(new_tmp)
    end
    @import_filedata[:zip_tmp] = new_tmp

    # Grab the list of unique basedirs over all entries.
    @import_filedata[:zip_tmp_subdirs] = @import_filedata[:zip_entry_names].map {|x| ::File.split(x)}.map {|x| x[0]}.uniq.reject {|x| x == "."}

    # mkdir all of the base directores we just pulled out, if they don't
    # already exist
    @import_filedata[:zip_tmp_subdirs].each {|sub|
      tmp_subdirs = ::File.join(@import_filedata[:zip_tmp],sub)
      if File.exists? tmp_subdirs
        unless (::File.directory?(tmp_subdirs) && File.writable?(tmp_subdirs))
          # if it exists but we can't write to it, give up
          raise DBImportError.new("Could not extract zip file to #{tmp_subdirs}")
        end
      else
        ::FileUtils.mkdir(tmp_subdirs)
      end
    }


    data.entries.each do |e|
      target = ::File.join(@import_filedata[:zip_tmp],e.name)
      ::File.unlink target if ::File.exists?(target) # Yep. Deleted.
      data.extract(e,target)
      if target =~ /^.*.xml$/
        target_data = ::File.open(target, "rb") {|f| f.read 1024}
        if import_filetype_detect(target_data) == :msf_xml
          @import_filedata[:zip_extracted_xml] = target
          #break
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

  private


  # Imports loot, tasks, and reports from an MSF ZIP report.
  # XXX: This function is stupidly long. It needs to be refactored.
  def import_msf_collateral(args={}, &block)
    data = ::File.open(args[:filename], "rb") {|f| f.read(f.stat.size)}
    wspace = args[:wspace] || args['wspace'] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    basedir = args[:basedir] || args['basedir'] || ::File.join(Msf::Config.install_root, "data", "msf")

    allow_yaml = false
    btag = nil

    doc = rexmlify(data)
    if doc.elements["MetasploitExpressV1"]
      m_ver = 1
      allow_yaml = true
      btag = "MetasploitExpressV1"
    elsif doc.elements["MetasploitExpressV2"]
      m_ver = 2
      allow_yaml = true
      btag = "MetasploitExpressV2"
    elsif doc.elements["MetasploitExpressV3"]
      m_ver = 3
      btag = "MetasploitExpressV3"
    elsif doc.elements["MetasploitExpressV4"]
      m_ver = 4
      btag = "MetasploitExpressV4"
    elsif doc.elements["MetasploitV4"]
      m_ver = 4
      btag = "MetasploitV4"
    else
      m_ver = nil
    end
    unless m_ver and btag
      raise DBImportError.new("Unsupported Metasploit XML document format")
    end

    host_info = {}
    doc.elements.each("/#{btag}/hosts/host") do |host|
      host_info[host.elements["id"].text.to_s.strip] = nils_for_nulls(host.elements["address"].text.to_s.strip)
    end

    # Import Loot
    doc.elements.each("/#{btag}/loots/loot") do |loot|
      next if bl.include? host_info[loot.elements["host-id"].text.to_s.strip]
      loot_info              = {}
      loot_info[:host]       = host_info[loot.elements["host-id"].text.to_s.strip]
      loot_info[:workspace]  = args[:wspace]
      loot_info[:ctype]      = nils_for_nulls(loot.elements["content-type"].text.to_s.strip)
      loot_info[:info]       = nils_for_nulls(unserialize_object(loot.elements["info"], allow_yaml))
      loot_info[:ltype]      = nils_for_nulls(loot.elements["ltype"].text.to_s.strip)
      loot_info[:name]       = nils_for_nulls(loot.elements["name"].text.to_s.strip)
      loot_info[:created_at] = nils_for_nulls(loot.elements["created-at"].text.to_s.strip)
      loot_info[:updated_at] = nils_for_nulls(loot.elements["updated-at"].text.to_s.strip)
      loot_info[:name]       = nils_for_nulls(loot.elements["name"].text.to_s.strip)
      loot_info[:orig_path]  = nils_for_nulls(loot.elements["path"].text.to_s.strip)
      loot_info[:task]       = args[:task]
      tmp = args[:ifd][:zip_tmp]
      loot_info[:orig_path].gsub!(/^\./,tmp) if loot_info[:orig_path]
      if !loot.elements["service-id"].text.to_s.strip.empty?
        unless loot.elements["service-id"].text.to_s.strip == "NULL"
          loot_info[:service] = loot.elements["service-id"].text.to_s.strip
        end
      end

      # Only report loot if we actually have it.
      # TODO: Copypasta. Seperate this out.
      if ::File.exists? loot_info[:orig_path]
        loot_dir = ::File.join(basedir,"loot")
        loot_file = ::File.split(loot_info[:orig_path]).last
        if ::File.exists? loot_dir
          unless (::File.directory?(loot_dir) && ::File.writable?(loot_dir))
            raise DBImportError.new("Could not move files to #{loot_dir}")
          end
        else
          ::FileUtils.mkdir_p(loot_dir)
        end
        new_loot = ::File.join(loot_dir,loot_file)
        loot_info[:path] = new_loot
        if ::File.exists?(new_loot)
          ::File.unlink new_loot # Delete it, and don't report it.
        else
          report_loot(loot_info) # It's new, so report it.
        end
        ::FileUtils.copy(loot_info[:orig_path], new_loot)
        yield(:msf_loot, new_loot) if block
      end
    end

    # Import Tasks
    doc.elements.each("/#{btag}/tasks/task") do |task|
      task_info = {}
      task_info[:workspace] = args[:wspace]
      # Should user be imported (original) or declared (the importing user)?
      task_info[:user] = nils_for_nulls(task.elements["created-by"].text.to_s.strip)
      task_info[:desc] = nils_for_nulls(task.elements["description"].text.to_s.strip)
      task_info[:info] = nils_for_nulls(unserialize_object(task.elements["info"], allow_yaml))
      task_info[:mod] = nils_for_nulls(task.elements["module"].text.to_s.strip)
      task_info[:options] = nils_for_nulls(task.elements["options"].text.to_s.strip)
      task_info[:prog] = nils_for_nulls(task.elements["progress"].text.to_s.strip).to_i
      task_info[:created_at] = nils_for_nulls(task.elements["created-at"].text.to_s.strip)
      task_info[:updated_at] = nils_for_nulls(task.elements["updated-at"].text.to_s.strip)
      if !task.elements["completed-at"].text.to_s.empty?
        task_info[:completed_at] = nils_for_nulls(task.elements["completed-at"].text.to_s.strip)
      end
      if !task.elements["error"].text.to_s.empty?
        task_info[:error] = nils_for_nulls(task.elements["error"].text.to_s.strip)
      end
      if !task.elements["result"].text.to_s.empty?
        task_info[:result] = nils_for_nulls(task.elements["result"].text.to_s.strip)
      end
      task_info[:orig_path] = nils_for_nulls(task.elements["path"].text.to_s.strip)
      tmp = args[:ifd][:zip_tmp]
      task_info[:orig_path].gsub!(/^\./,tmp) if task_info[:orig_path]

      # Only report a task if we actually have it.
      # TODO: Copypasta. Seperate this out.
      if ::File.exists? task_info[:orig_path]
        tasks_dir = ::File.join(basedir,"tasks")
        task_file = ::File.split(task_info[:orig_path]).last
        if ::File.exists? tasks_dir
          unless (::File.directory?(tasks_dir) && ::File.writable?(tasks_dir))
            raise DBImportError.new("Could not move files to #{tasks_dir}")
          end
        else
          ::FileUtils.mkdir_p(tasks_dir)
        end
        new_task = ::File.join(tasks_dir,task_file)
        task_info[:path] = new_task
        if ::File.exists?(new_task)
          ::File.unlink new_task # Delete it, and don't report it.
        else
          report_task(task_info) # It's new, so report it.
        end
        ::FileUtils.copy(task_info[:orig_path], new_task)
        yield(:msf_task, new_task) if block
      end
    end

    # Import Reports
    doc.elements.each("/#{btag}/reports/report") do |report|
      tmp = args[:ifd][:zip_tmp]
      report_info              = {}
      report_info[:workspace]  = args[:wspace]
      # Should user be imported (original) or declared (the importing user)?
      report_info[:user]       = nils_for_nulls(report.elements["created-by"].text.to_s.strip)
      report_info[:options]    = nils_for_nulls(report.elements["options"].text.to_s.strip)
      report_info[:rtype]      = nils_for_nulls(report.elements["rtype"].text.to_s.strip)
      report_info[:created_at] = nils_for_nulls(report.elements["created-at"].text.to_s.strip)
      report_info[:updated_at] = nils_for_nulls(report.elements["updated-at"].text.to_s.strip)
      report_info[:orig_path]  = nils_for_nulls(report.elements["path"].text.to_s.strip)
      report_info[:task]       = args[:task]
      report_info[:orig_path].gsub!(/^\./, tmp) if report_info[:orig_path]

      # Only report a report if we actually have it.
      # TODO: Copypasta. Seperate this out.
      if ::File.exists? report_info[:orig_path]
        reports_dir = ::File.join(basedir,"reports")
        report_file = ::File.split(report_info[:orig_path]).last
        if ::File.exists? reports_dir
          unless (::File.directory?(reports_dir) && ::File.writable?(reports_dir))
            raise DBImportError.new("Could not move files to #{reports_dir}")
          end
        else
          ::FileUtils.mkdir_p(reports_dir)
        end
        new_report = ::File.join(reports_dir,report_file)
        report_info[:path] = new_report
        if ::File.exists?(new_report)
          ::File.unlink new_report
        else
          report_report(report_info)
        end
        ::FileUtils.copy(report_info[:orig_path], new_report)
        yield(:msf_report, new_report) if block
      end
    end

  end
end