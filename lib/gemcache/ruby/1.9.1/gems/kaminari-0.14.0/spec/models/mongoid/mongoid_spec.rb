require 'spec_helper'

if defined? Mongoid
  describe Kaminari::MongoidExtension do
    before(:each) do
      41.times do
        User.create!({:salary => 1})
      end
    end

    describe '#page' do

      context 'page 1' do
        subject { User.page 1 }
        it { should be_a Mongoid::Criteria }
        its(:current_page) { should == 1 }
        its(:limit_value) { should == 25 }
        its(:total_pages) { should == 2 }
        it { should skip(0) }
      end

      context 'page 2' do
        subject { User.page 2 }
        it { should be_a Mongoid::Criteria }
        its(:current_page) { should == 2 }
        its(:limit_value) { should == 25 }
        its(:total_pages) { should == 2 }
        it { should skip 25 }
      end

      context 'page "foobar"' do
        subject { User.page 'foobar' }
        it { should be_a Mongoid::Criteria }
        its(:current_page) { should == 1 }
        its(:limit_value) { should == 25 }
        its(:total_pages) { should == 2 }
        it { should skip 0 }
      end

      shared_examples 'complete valid pagination' do
        if Mongoid::VERSION =~ /^3/
          its(:selector) { should == {'salary' => 1} }
        else
          its(:selector) { should == {:salary => 1} }
        end
        its(:current_page) { should == 2 }
        its(:limit_value) { should == 25 }
        its(:total_pages) { should == 2 }
        it { should skip 25 }
      end

      context 'with criteria before' do
        subject { User.where(:salary => 1).page 2 }
        it_should_behave_like 'complete valid pagination'
      end

      context 'with criteria after' do
        subject { User.page(2).where(:salary => 1) }
        it_should_behave_like 'complete valid pagination'
      end
    end

    describe '#per' do
      subject { User.page(2).per(10) }
      it { should be_a Mongoid::Criteria }
      its(:current_page) { should == 2 }
      its(:limit_value) { should == 10 }
      its(:total_pages) { should == 5 }
      it { should skip 10 }
    end

    describe '#page in embedded documents' do
      before do
        @mongo_developer = MongoMongoidExtensionDeveloper.new
        @mongo_developer.frameworks.new(:name => "rails", :language => "ruby")
        @mongo_developer.frameworks.new(:name => "merb", :language => "ruby")
        @mongo_developer.frameworks.new(:name => "sinatra", :language => "ruby")
        @mongo_developer.frameworks.new(:name => "cakephp", :language => "php")
        @mongo_developer.frameworks.new(:name => "tornado", :language => "python")
      end

      context 'page 1' do
        subject { @mongo_developer.frameworks.page(1).per(1) }
        it { should be_a Mongoid::Criteria }
        its(:total_count) { should == 5 }
        its(:limit_value) { should == 1 }
        its(:current_page) { should == 1 }
        its(:total_pages) { should == 5 }
      end

      context 'with criteria after' do
        subject { @mongo_developer.frameworks.page(1).per(2).where(:language => "ruby") }
        it { should be_a Mongoid::Criteria }
        its(:total_count) { should == 3 }
        its(:limit_value) { should == 2 }
        its(:current_page) { should == 1 }
        its(:total_pages) { should == 2 }
      end

      context 'with criteria before' do
        subject { @mongo_developer.frameworks.where(:language => "ruby").page(1).per(2) }
        it { should be_a Mongoid::Criteria }
        its(:total_count) { should == 3 }
        its(:limit_value) { should == 2 }
        its(:current_page) { should == 1 }
        its(:total_pages) { should == 2 }
      end
    end
  end
end
