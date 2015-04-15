require 'spec_helper'

RSpec.describe Msf::ModuleSet do
  subject(:module_set) {
    described_class.new(module_type)
  }

  let(:module_type) {
    FactoryGirl.generate :mdm_module_detail_mtype
  }

  context '#rank_modules' do
    subject(:rank_modules) {
      module_set.send(:rank_modules)
    }

    context 'with Msf::SymbolicModule' do
      before(:each) do
        module_set['a'] = Msf::SymbolicModule
        module_set['b'] = Msf::SymbolicModule
        module_set['c'] = Msf::SymbolicModule
      end

      context 'create' do
        context 'returns nil' do
          before(:each) do
            allow(module_set).to receive(:create).and_return(nil)
          end

          specify {
            expect {
              rank_modules
            }.not_to raise_error
          }
        end

        context 'does not return nil' do
          context 'with Rank' do
            it 'is ranked using Rank'
          end

          context 'without Rank' do
            it 'is ranked as Normal'
          end
        end
      end
    end

    context 'without Msf::SymbolicModule' do
      context 'with Rank' do
        it 'is ranked using Rank'
      end

      context 'without Rank' do
        it 'is ranked as Normal'
      end
    end
  end
end