require 'spec_helper'

RSpec.describe ::Msf::Ui::Console::CommandDispatcher::Common do
  let(:subject) do
    dummy_class = Class.new
    dummy_class.extend(described_class)
  end

  def with_path_extensions(original_paths)
    extensions = ['rb', 'br', 'r', 'b']
    extensions += ['py', 'yp', 'p', 'y']
    extensions += ['go', 'og', 'g', 'o']
    extensions += ['']

    paths_with_extensions = extensions.flat_map do |extension|
      original_paths.map { |path| "#{path}.#{extension}" }
    end
    original_paths + paths_with_extensions
  end

  describe 'Trimming a path of errors' do
    context 'when a user is inputting a Module path' do
      let(:valid_path) { 'windows/smb/ms08_067_netapi' }
      let(:all_paths) do
        [
          './exploits/windows/smb/ms08_067_netapi',
          '/exploits/windows/smb/ms08_067_netapi',
          '.exploits/windows/smb/ms08_067_netapi',
          'exploits/windows/smb/ms08_067_netapi',

          './windows/smb/ms08_067_netapi',
          '/windows/smb/ms08_067_netapi',
          '.windows/smb/ms08_067_netapi',

          valid_path
        ]
      end

      it 'corrects the module paths to be valid' do
        with_path_extensions(all_paths).each do |path|
          expect(subject.trim_path(path, 'exploits')).to eql(valid_path)
        end
      end
    end

    context 'when a user is inputting a Payload path' do
      let(:valid_path) { 'windows/x64/vncinject/reverse_winhttps' }
      let(:all_paths) do
        [
          './payload/windows/x64/vncinject/reverse_winhttps',
          '/payload/windows/x64/vncinject/reverse_winhttps',
          '.payload/windows/x64/vncinject/reverse_winhttps',
          'payload/windows/x64/vncinject/reverse_winhttps',

          './windows/x64/vncinject/reverse_winhttps',
          '/windows/x64/vncinject/reverse_winhttps',
          '.windows/x64/vncinject/reverse_winhttps',

          valid_path
        ]
      end

      it "when a user is inputting a Modules path" do
        with_path_extensions(all_paths).each do |path|
          expect(subject.trim_path(path, 'payload')).to eql(valid_path)
        end
      end
    end
  end
end
