module Msf::DBManager::Task
  #
  # Find or create a task matching this type/data
  #
  def find_or_create_task(opts)
    report_task(opts)
  end

  def report_task(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    path = opts.delete(:path) || (raise RuntimeError, "A task :path is required")

    ret = {}

    user      = opts.delete(:user)
    desc      = opts.delete(:desc)
    error     = opts.delete(:error)
    info      = opts.delete(:info)
    mod       = opts.delete(:mod)
    options   = opts.delete(:options)
    prog      = opts.delete(:prog)
    result    = opts.delete(:result)
    completed_at = opts.delete(:completed_at)
    task      = wspace.tasks.new

    task.created_by = user
    task.description = desc
    task.error = error if error
    task.info = info
    task.module = mod
    task.options = options
    task.path = path
    task.progress = prog
    task.result = result if result
    msf_import_timestamps(opts,task)
    # Having blank completed_ats, while accurate, will cause unstoppable tasks.
    if completed_at.nil? || completed_at.empty?
      task.completed_at = opts[:updated_at]
    else
      task.completed_at = completed_at
    end
    task.save!
    ret[:task] = task
  }
  end

  #
  # This methods returns a list of all tasks in the database
  #
  def tasks(wspace=framework.db.workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.tasks
  }
  end
end