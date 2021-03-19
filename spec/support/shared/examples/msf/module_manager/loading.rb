RSpec.shared_examples_for 'Msf::ModuleManager::Loading' do
  let(:parent_path) do
    Metasploit::Framework.root.join('modules')
  end

  let(:module_basename) do
    [basename_prefix, '.rb']
  end

  context '#load_error_by_name' do
    it 'should return errors associated with that module' do
      Tempfile.open(module_basename) do |tempfile|
        module_path = tempfile.path
        modification_time = File.mtime(module_path).to_i
        name = 'auxiliary/mock_dir/mock_dir/mock_file'

        subject.send(:module_info_by_path)[module_path] = {
            reference_name: 'mock_dir/mock_dir/mock_file',
            type: 'auxiliary',
            parent_path: parent_path,
            modification_time: modification_time
        }
        subject.send(:module_load_error_by_path)[module_path] = 'mock error'

        subject.load_error_by_name(name)
        expect(subject.load_error_by_name(name)).to(eql 'mock error')
      end
    end

    it 'should return errors associated with that module, even without a prefixed module type' do
      Tempfile.open(module_basename) do |tempfile|
        module_path = tempfile.path
        modification_time = File.mtime(module_path).to_i
        name = 'mock_dir/mock_dir/mock_file'

        subject.send(:module_info_by_path)[module_path] = {
            reference_name: 'mock_dir/mock_dir/mock_file',
            type: 'auxiliary',
            parent_path: parent_path,
            modification_time: modification_time
        }
        subject.send(:module_load_error_by_path)[module_path] = 'mock error'

        subject.load_error_by_name(name)
        expect(subject.load_error_by_name(name)).to(eql 'mock error')
      end
    end

    it 'should recognise we are passing a module alias and return errors associated with that aliased module' do
      Tempfile.open(module_basename) do |tempfile|
        module_path = tempfile.path
        modification_time = File.mtime(module_path).to_i
        name = 'auxiliary/mock_dir/mock_dir/mock_file'

        subject.send(:module_info_by_path)[module_path] = {
            reference_name: 'mock_dir/mock_dir/mock_file',
            type: 'auxiliary',
            parent_path: parent_path,
            modification_time: modification_time
        }

        subject.send(:module_load_error_by_path)[module_path] = 'mock error'
        subject.send(:aliases)['auxiliary/mock_dir/mock_dir/mock_file_alias'] = 'auxiliary/mock_dir/mock_dir/mock_file'
        subject.send(:inv_aliases)['auxiliary/mock_dir/mock_dir/mock_file'] = 'auxiliary/mock_dir/mock_dir/mock_file_alias'

        subject.load_error_by_name(name)
        expect(subject.load_error_by_name(name)).to(eql 'mock error')
      end
    end

    it 'should return nil as this module will have no associated errors' do
      Tempfile.open(module_basename) do |tempfile|
        module_path = tempfile.path
        modification_time = File.mtime(module_path).to_i
        name = 'auxiliary/mock_dir/mock_dir/mock_file'

        subject.send(:module_info_by_path)[module_path] = {
            reference_name: 'mock_dir/mock_dir/mock_file',
            type: 'auxiliary',
            parent_path: parent_path,
            modification_time: modification_time
        }

        subject.load_error_by_name(name)
        expect(subject.load_error_by_name(name)).to(eql nil)
      end
    end
  end

  context '#file_changed?' do
    let(:module_basename) do
      [basename_prefix, '.rb']
    end

    it 'should return true if module info is not cached' do
      Tempfile.open(module_basename) do |tempfile|
        module_path = tempfile.path

        expect(subject.send(:module_info_by_path)[module_path]).to be_nil
        expect(subject.file_changed?(module_path)).to be_truthy
      end
    end

    it 'should return true if the cached type is Msf::MODULE_PAYLOAD' do
      Tempfile.open(module_basename) do |tempfile|
        module_path = tempfile.path
        modification_time = File.mtime(module_path)

        subject.send(:module_info_by_path)[module_path] = {
            # :modification_time must match so that it is the :type that is causing the `true` and not the
            # :modification_time causing the `true`.
            :modification_time => modification_time,
            :type => Msf::MODULE_PAYLOAD
        }

        expect(subject.file_changed?(module_path)).to be_truthy
      end
    end

    context 'with cache module info and not a payload module' do
      it 'should return true if the file does not exist on the file system' do
        tempfile = Tempfile.new(module_basename)
        module_path = tempfile.path
        modification_time = File.mtime(module_path).to_i

        subject.send(:module_info_by_path)[module_path] = {
            :modification_time => modification_time
        }

        tempfile.unlink

        expect(File.exist?(module_path)).to be_falsey
        expect(subject.file_changed?(module_path)).to be_truthy
      end

      it 'should return true if modification time does not match the cached modification time' do
        Tempfile.open(module_basename) do |tempfile|
          module_path = tempfile.path
          modification_time = File.mtime(module_path).to_i
          cached_modification_time = (modification_time * rand).to_i

          subject.send(:module_info_by_path)[module_path] = {
              :modification_time => cached_modification_time
          }

          expect(cached_modification_time).not_to eq modification_time
          expect(subject.file_changed?(module_path)).to be_truthy
        end
      end

      it 'should return false if modification time does match the cached modification time' do
        Tempfile.open(module_basename) do |tempfile|
          module_path = tempfile.path
          modification_time = File.mtime(module_path).to_i
          cached_modification_time = modification_time

          subject.send(:module_info_by_path)[module_path] = {
              :modification_time => cached_modification_time
          }

          expect(cached_modification_time).to eq modification_time
          expect(subject.file_changed?(module_path)).to be_falsey
        end
      end
    end
  end

  context '#on_module_load' do
    def on_module_load
      module_manager.on_module_load(klass, type, reference_name, options)
    end

    let(:klass) do
      Class.new(Msf::Auxiliary)
    end

    let(:module_set) do
      module_manager.module_set(type)
    end

    let(:namespace_module) do
      double('Namespace Module', :parent_path => parent_path)
    end

    let(:options) do
      {
          'files' => [
              path
          ],
          'paths' => [
              reference_name
          ],
          'type' => type
      }
    end

    let(:path) do
      type_directory = Mdm::Module::Detail::DIRECTORY_BY_TYPE[type]

      File.join(parent_path, type_directory, "#{reference_name}.rb")
    end

    let(:reference_name) do
      'admin/2wire/xslt_password_reset'
    end

    let(:type) do
      klass.type
    end

    before(:example) do
      allow(klass).to receive(:module_parent).and_return(namespace_module)
    end

    it "should add module to type's module_set" do
      expect(module_set).to receive(:add_module).with(
          klass,
          reference_name,
          options
      )

      on_module_load
    end

    it 'should call cache_in_memory' do
      expect(module_manager).to receive(:cache_in_memory)

      on_module_load
    end

    it 'should pass class to #auto_subscribe_module' do
      expect(module_manager).to receive(:auto_subscribe_module).with(klass)

      on_module_load
    end

    it 'should fire on_module_load event with class' do
      expect(framework.events).to receive(:on_module_load).with(
          reference_name,
          klass
      )

      on_module_load
    end
  end
end
