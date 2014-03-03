shared_context 'Msf::ThreadManager' do
  after(:each) do
    thread_manager.each do |thread|
      thread.kill
      thread.join
    end

    thread_manager.monitor.kill
    thread_manager.monitor.join
  end
end