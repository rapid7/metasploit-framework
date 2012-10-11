require 'spec_helper'

if defined? ActiveRecord

  describe 'default per_page' do
    describe 'AR::Base' do
      subject { ActiveRecord::Base }
      it { should_not respond_to :paginates_per }
    end

    subject { User.page 0 }

    context 'by default' do
      its(:limit_value) { should == 25 }
    end

    context 'when explicitly set via paginates_per' do
      before { User.paginates_per 1326 }
      its(:limit_value) { should == 1326 }
      after { User.paginates_per nil }
    end

    describe "default per_page value's independency per model" do
      context "when User's default per_page was changed" do
        before { User.paginates_per 1326 }
        subject { Book.page 0 }
        its(:limit_value) { should == 25 }
        after { User.paginates_per nil }
      end
    end
  end
end
