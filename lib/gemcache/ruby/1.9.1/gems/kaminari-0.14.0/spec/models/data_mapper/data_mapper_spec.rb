require 'spec_helper'

if defined? DataMapper
  describe Kaminari::DataMapperExtension do
    before do
      100.times do |i|
        User.create(:name => "User#{i}", :age => i)
      end

      worker0 = User[0]
      50.times do |i|
        worker0.projects << Project.create(:name => "Project#{i}")
      end
      worker0.projects.save
    end

    describe 'Collection' do
      subject{ User.all }
      it { should respond_to(:page) }
      it { should_not respond_to(:per) }
    end

    describe 'Model' do
      subject{ User }
      it { should respond_to(:page) }
      it { should respond_to(:default_per_page) }
      it { should_not respond_to(:per) }
    end

    describe '#page' do
      context 'page 0' do
        subject { User.all(:age.gte => 60).page 0 }
        it { should be_a DataMapper::Collection }
        its(:current_page) { should == 1 }
        its('query.limit') { should == 25 }
        its('query.offset') { should == 0 }
        its(:total_count) { should == User.count(:age.gte => 60) }
        its(:total_pages) { should == 2 }
      end

      context 'page 1' do
        subject { User.all(:age.gte => 0).page 1 }
        it { should be_a DataMapper::Collection }
        its(:current_page) { should == 1 }
        its('query.limit') { should == 25 }
        its('query.offset') { should == 0 }
        its(:total_count) { should == 100 }
        its(:total_pages) { should == 4 }
      end

      context 'page 2' do
        subject { User.page 2 }
        it { should be_a DataMapper::Collection }
        its(:current_page) { should == 2 }
        its(:limit_value) { should == 25 }
        its('query.limit') { should == 25 }
        its('query.offset') { should == 25 }
        its(:total_count) { should == 100 }
        its(:total_pages) { should == 4 }
      end

      context 'page "foobar"' do
        subject { User.page 'foobar' }
        it { should be_a DataMapper::Collection }
        its(:current_page) { should == 1 }
        its('query.limit') { should == 25 }
        its('query.offset') { should == 0 }
        its(:total_count) { should == 100 }
        its(:total_pages) { should == 4 }
      end

      context 'with criteria before' do
        subject { User.all(:age.gt => 60).page 2 }
        it { should be_a DataMapper::Collection }
        its(:current_page) { should == 2 }
        its('query.limit') { should == 25 }
        its('query.offset') { should == 25 }
        its(:total_count) { should == User.count(:age.gt => 60) }
        its(:total_pages) { should == 2 }
      end

      context 'with criteria after' do
        subject { User.page(2).all(:age.gt => 60) }
        it { should be_a DataMapper::Collection }
        its(:current_page) { should == 2 }
        its('query.limit') { should == 25 }
        its('query.offset') { should == 25 }
        its(:total_count) { should == User.count(:age.gt => 60) }
        its(:total_pages) { should == 2 }
      end
    end

    describe '#per' do
      context 'on simple query' do
        subject { User.page(2).per(20) }
        it { should be_a DataMapper::Collection }
        its(:current_page) { should == 2 }
        its('query.limit') { should == 20 }
        its(:limit_value) { should == 20 }
        its('query.offset') { should == 20 }
        its(:total_count) { should == 100 }
        its(:total_pages) { should == 5 }
      end

      context 'on query with condition' do
        subject { User.page(5).all(:age.lte => 80).per(13) }
        its(:current_page) { should == 5 }
        its('query.limit') { should == 13 }
        its('query.offset') { should == 52 }
        its(:total_count) { should == 81 }
        its(:total_pages) { should == 7 }
      end

      context 'on query with order' do
        subject { User.page(5).all(:age.lte => 80, :order => [:age.asc]).per(13) }
        it('includes user with age 52') { should include(User.first(:age => 52)) }
        it('does not include user with age 51') { should_not include(User.first(:age => 51)) }
        it('includes user with age 52') { should include(User.first(:age => 64)) }
        it('does not include user with age 51') { should_not include(User.first(:age => 65)) }
        its(:current_page) { should == 5 }
        its('query.limit') { should == 13 }
        its('query.offset') { should == 52 }
        its(:total_count) { should == 81 }
        its(:total_pages) { should == 7 }
      end

      context 'on chained queries' do
        subject { User.all(:age.gte => 50).page(3).all(:age.lte => 80).per(13) }
        its(:current_page) { should == 3 }
        its('query.limit') { should == 13 }
        its('query.offset') { should == 26 }
        its(:total_count) { should == 31 }
        its(:total_pages) { should == 3 }
      end

      context 'on query on association' do
        subject { User[0].projects.page(3).all(:name.like => 'Project%').per(5) }
        its(:current_page) { should == 3 }
        its('query.limit') { should == 5 }
        its('query.offset') { should == 10 }
        its(:total_count) { should == 50 }
        its(:total_pages) { should == 10 }
      end

      context 'on query with association conditions' do
        subject { User.page(3).all(:projects => Project.all).per(5) }
        its(:current_page) { should == 3 }
        its('query.limit') { should == 5 }
        its('query.offset') { should == 10 }
        its(:total_count) { should == 50 }
        its(:total_pages) { should == 10 }
      end
    end
  end
end
