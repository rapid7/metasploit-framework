RSpec.shared_examples_for 'Msf::Module::ModuleInfo' do
  context 'CONSTANTS' do
    context 'UpdateableOptions' do
      subject(:updateable_options) {
        described_class::UpdateableOptions
      }

      it { is_expected.to match_array(%w{Name Description Alias PayloadCompat Stance})}
    end
  end

  it { is_expected.to respond_to :alias }
  it { is_expected.to respond_to :description }
  it { is_expected.to respond_to :disclosure_date }
  it { is_expected.to respond_to_protected :info_fixups }
  it { is_expected.to respond_to_protected :merge_check_key }
  it { is_expected.to respond_to_protected :merge_info }
  it { is_expected.to respond_to_protected :merge_info_advanced_options }
  it { is_expected.to respond_to_protected :merge_info_alias }
  it { is_expected.to respond_to_protected :merge_info_description }
  it { is_expected.to respond_to_protected :merge_info_evasion_options }
  it { is_expected.to respond_to_protected :merge_info_name }
  it { is_expected.to respond_to_protected :merge_info_options }
  it { is_expected.to respond_to_protected :merge_info_string }
  it { is_expected.to respond_to_protected :merge_info_version }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to_protected :update_info }
end
