require 'spec_helper'
require 'rex/text'

RSpec.describe Msf::Payload::Adapter::Fetch::LinuxOptions do
  let(:base_class) do
    Class.new do
      attr_reader :registered

      def initialize(_info = {})
        @registered = []
      end

      def register_options(opts, *)
        @registered.concat(opts)
      end
    end
  end

  let(:container) do
    host = Class.new(base_class) { include Msf::Payload::Adapter::Fetch::LinuxOptions }.new
    Msf::OptionContainer.new(host.registered)
  end

  # FETCH_WRITABLE_DIR is hidden via `conditions:` when FETCH_FILELESS != none, but launch-time
  # validation (OptionContainer#validate) ignores `conditions:` and only checks `required?`.
  # It must therefore not be statically required.
  it 'does not make FETCH_WRITABLE_DIR statically required' do
    expect(container['FETCH_WRITABLE_DIR'].required?).to be false
  end
end
