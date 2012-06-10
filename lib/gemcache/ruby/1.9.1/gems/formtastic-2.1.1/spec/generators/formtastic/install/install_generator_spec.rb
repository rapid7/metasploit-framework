require 'spec_helper'

# Generators are not automatically loaded by Rails
require 'generators/formtastic/install/install_generator'

describe Formtastic::InstallGenerator do
  # Tell the generator where to put its output (what it thinks of as Rails.root)
  destination File.expand_path("../../../../../tmp", __FILE__)

  before { prepare_destination }

  describe 'no arguments' do
    before { run_generator  }

    describe 'config/initializers/formtastic.rb' do
      subject { file('config/initializers/formtastic.rb') }
      it { should exist }
      it { should contain "# Please note: If you're subclassing Formtastic::FormBuilder" }
    end

    describe 'lib/templates/erb/scaffold/_form.html.erb' do
      subject { file('lib/templates/erb/scaffold/_form.html.erb') }
      it { should exist }
      it { should contain "<%%= semantic_form_for @<%= singular_name %> do |f| %>" }
    end
  end

  describe 'haml' do
    before { run_generator %w(--template-engine haml) }

    describe 'lib/templates/erb/scaffold/_form.html.haml' do
      subject { file('lib/templates/haml/scaffold/_form.html.haml') }
      it { should exist }
      it { should contain "= semantic_form_for @<%= singular_name %> do |f|" }
    end
  end

  describe 'slim' do
    before { run_generator %w(--template-engine slim) }

    describe 'lib/templates/erb/scaffold/_form.html.slim' do
      subject { file('lib/templates/slim/scaffold/_form.html.slim') }
      it { should exist }
      it { should contain "= semantic_form_for @<%= singular_name %> do |f|" }
    end
  end
end
