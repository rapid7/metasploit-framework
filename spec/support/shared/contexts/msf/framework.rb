shared_context 'Msf::Framework' do
  include_context 'Msf::ThreadManager' do
    let(:thread_manager) do
      framework.threads
    end
  end

  let(:framework) do
    Msf::Framework.new
  end
end