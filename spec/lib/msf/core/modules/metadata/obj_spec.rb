require 'spec_helper'
require 'msf/core/modules/metadata/obj'

RSpec.describe Msf::Modules::Metadata::Obj do
  let(:module_instance) do
    double('ModuleInstance',
      name: 'Test Payload',
      realname: 'payload/windows/test',
      aliases: [],
      disclosure_date: nil,
      rank: 300,
      type: 'payload',
      description: 'Test Description',
      author: ['test_author'],
      references: [],
      post_auth?: false,
      default_cred?: false,
      platform_to_s: 'Windows',
      platform: Msf::Module::PlatformList.new('Windows'),
      arch_to_s: 'x86',
      datastore: { 'RPORT' => 4444 },
      file_path: '/modules/payloads/test.rb',
      refname: 'windows/test',
      needs_cleanup: false,
      has_check?: false,
      notes: {},
      session_types: [],
      payload_type: Msf::Payload::Type::Single,
      staged?: false,
      cached_size: 1024,
      dynamic_size?: false
    )
  end

  before do
    allow(module_instance.class).to receive(:refname).and_return('windows/test')
    allow(::File).to receive(:mtime).and_return(Time.now)
  end

  describe 'serialization and deserialization' do
    it 'correctly serializes and deserializes payload_cached_size' do
      obj = described_class.new(module_instance)
      expect(obj.payload_cached_size).to eq(1024)

      json = obj.to_json
      hash = JSON.parse(json)
      
      expect(hash['payload_cached_size']).to eq(1024)

      restored_obj = described_class.from_hash(hash)
      expect(restored_obj.payload_cached_size).to eq(1024)
    end
    
    context 'with dynamic payload_cached_size' do
      let(:module_instance_dynamic) do
        double('ModuleInstanceDynamic',
          name: 'Dynamic Payload',
          realname: 'payload/windows/dynamic',
          aliases: [],
          disclosure_date: nil,
          rank: 300,
          type: 'payload',
          description: 'Test Description',
          author: ['test_author'],
          references: [],
          post_auth?: false,
          default_cred?: false,
          platform_to_s: 'Windows',
          platform: Msf::Module::PlatformList.new('Windows'),
          arch_to_s: 'x86',
          datastore: { 'RPORT' => 4444 },
          file_path: '/modules/payloads/dynamic.rb',
          refname: 'windows/dynamic',
          needs_cleanup: false,
          has_check?: false,
          notes: {},
          session_types: [],
          payload_type: Msf::Payload::Type::Single,
          staged?: false,
          cached_size: nil,
          dynamic_size?: true
        )
      end

      before do
        allow(module_instance_dynamic.class).to receive(:refname).and_return('windows/dynamic')
        allow(module_instance_dynamic).to receive(:shortname).and_return('dynamic')
        allow(module_instance_dynamic).to receive(:module_info).and_return({})
        
        replicant = double('Replicant')
        generated_payload = double('GeneratedPayload', bytesize: 250000)
        allow(replicant).to receive(:generate_simple).and_return(generated_payload)
        allow(module_instance_dynamic).to receive(:replicant).and_return(replicant)
      end

      it 'generates a size and serializes/deserializes it' do
        obj = described_class.new(module_instance_dynamic)
        expect(obj.payload_cached_size).to eq(250000)

        json = obj.to_json
        hash = JSON.parse(json)
        
        expect(hash['payload_cached_size']).to eq(250000)

        restored_obj = described_class.from_hash(hash)
        expect(restored_obj.payload_cached_size).to eq(250000)
      end
    end
  end
end
