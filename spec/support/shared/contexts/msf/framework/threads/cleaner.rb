shared_context 'Msf::Framework#threads cleaner' do
  after(:each) do
    # explicitly kill threads so that they don't exhaust connection pool
    thread_manager = framework.threads

    thread_manager.each do |thread|
      thread.kill
      # ensure killed thread is cleaned up by VM
      thread.join
    end

    thread_manager.monitor.kill
    # ensure killed thread is cleaned up by VM
    thread_manager.monitor.join
  end
end