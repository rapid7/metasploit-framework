shared_context 'Metasploit::Framework::Thread::Manager cleaner' do
  after(:each) do
    if thread_manager
      # explicitly kill threads so that they don't exhaust connection pool or waste memory
      threads = thread_manager.list

      threads.each do |thread|
        thread.kill
      end
    end
  end
end