require 'spec_helper'

if defined? ActiveRecord

  describe 'max per_page' do
    describe 'AR::Base' do
      subject { ActiveRecord::Base }
      it { should_not respond_to :max_paginates_per }
    end

    subject { User.page(0).per(100) }

    context 'by default' do
      its(:limit_value) { should == 100 }
    end

    context 'when explicitly set via max_paginates_per' do
      before { User.max_paginates_per 10 }
      its(:limit_value) { should == 10 }
      after { User.max_paginates_per nil }
    end

    describe "max per_page value's independency per model" do
      context "when User's max per_page was changed" do
        before { User.max_paginates_per 10 }
        subject { Book.page(0).per(100) }
        its(:limit_value) { should == 100 }
        after { User.max_paginates_per nil }
      end
    end
  end
end
