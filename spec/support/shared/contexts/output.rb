shared_context 'output' do
  let(:output) do
    capture(:stdout) {
      subject
    }
  end

  let(:quietly) do
    Kernel.quietly {
      subject
    }
  end
end
