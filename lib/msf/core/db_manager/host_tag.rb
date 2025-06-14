module Msf::DBManager::HostTag
  # This is only exercised by MSF3 XML importing for now. Needs the wait
  # conditions and return hash as well.
  def report_host_tag(opts)
    opts = opts.clone() # protect the original caller's opts
    name = opts.delete(:name)
    raise Msf::DBImportError.new("Missing required option :name") unless name
    addr = opts.delete(:addr)
    raise Msf::DBImportError.new("Missing required option :addr") unless addr
  ::ApplicationRecord.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    raise Msf::DBImportError.new("Missing required option :workspace") unless wspace
    host = nil
    report_host(:workspace => wspace, :address => addr)


    host = get_host(:workspace => wspace, :address => addr)
    desc = opts[:desc]
    summary = opts[:summary]
    detail = opts[:detail]
    crit = opts[:crit]
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
