module Msf::DBManager::Tag
  # This is only exercised by MSF3 XML importing for now. Needs the wait
  # conditions and return hash as well.
  def report_host_tag(opts)
    name = opts.delete(:name)
    raise DBImportError.new("Missing required option :name") unless name
    addr = opts.delete(:addr)
    raise DBImportError.new("Missing required option :addr") unless addr
    wspace = opts.delete(:wspace)
    raise DBImportError.new("Missing required option :wspace") unless wspace
    ::ActiveRecord::Base.connection_pool.with_connection {
      if wspace.kind_of? String
        wspace = find_workspace(wspace)
      end

      host = nil
      report_host(:workspace => wspace, :address => addr)


      host = get_host(:workspace => wspace, :address => addr)
      desc = opts.delete(:desc)
      summary = opts.delete(:summary)
      detail = opts.delete(:detail)
      crit = opts.delete(:crit)
      possible_tags = Mdm::Tag.includes(:hosts).where("hosts.workspace_id = ? and tags.name = ?", wspace.id, name).order("tags.id DESC").limit(1)
      tag = (possible_tags.blank? ? Mdm::Tag.new : possible_tags.first)
      tag.name = name
      tag.desc = desc
      tag.report_summary = !!summary
      tag.report_detail = !!detail
      tag.critical = !!crit
      tag.hosts = tag.hosts | [host]
      tag.save! if tag.changed?
    }
  end
end