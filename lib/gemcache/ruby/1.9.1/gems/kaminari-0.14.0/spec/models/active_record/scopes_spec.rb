require 'spec_helper'

if defined? ActiveRecord

  shared_examples_for 'the first page' do
    it { should have(25).users }
    its('first.name') { should == 'user001' }
  end

  shared_examples_for 'blank page' do
    it { should have(0).users }
  end

  describe Kaminari::ActiveRecordExtension do
    before do
      1.upto(100) {|i| User.create! :name => "user#{'%03d' % i}", :age => (i / 10)}
      1.upto(100) {|i| GemDefinedModel.create! :name => "user#{'%03d' % i}", :age => (i / 10)}
    end

    [User, Admin, GemDefinedModel].each do |model_class|
      context "for #{model_class}" do
        describe '#page' do
          context 'page 1' do
            subject { model_class.page 1 }
            it_should_behave_like 'the first page'
          end

          context 'page 2' do
            subject { model_class.page 2 }
            it { should have(25).users }
            its('first.name') { should == 'user026' }
          end

          context 'page without an argument' do
            subject { model_class.page }
            it_should_behave_like 'the first page'
          end

          context 'page < 1' do
            subject { model_class.page 0 }
            it_should_behave_like 'the first page'
          end

          context 'page > max page' do
            subject { model_class.page 5 }
            it_should_behave_like 'blank page'
          end

          describe 'ensure #order_values is preserved' do
            subject { model_class.order('id').page 1 }
            its('order_values.uniq') { should == ['id'] }
          end
        end

        describe '#per' do
          context 'page 1 per 5' do
            subject { model_class.page(1).per(5) }
            it { should have(5).users }
            its('first.name') { should == 'user001' }
          end
        end

        describe '#padding' do
          context 'page 1 per 5 padding 1' do
            subject { model_class.page(1).per(5).padding(1) }
            it { should have(5).users }
            its('first.name') { should == 'user002' }
          end
        end

        describe '#total_pages' do
          context 'per 25 (default)' do
            subject { model_class.page }
            its(:total_pages) { should == 4 }
          end

          context 'per 7' do
            subject { model_class.page(2).per(7) }
            its(:total_pages) { should == 15 }
          end

          context 'per 65536' do
            subject { model_class.page(50).per(65536) }
            its(:total_pages) { should == 1 }
          end

          context 'per 0 (using default)' do
            subject { model_class.page(50).per(0) }
            its(:total_pages) { should == 4 }
          end

          context 'per -1 (using default)' do
            subject { model_class.page(5).per(-1) }
            its(:total_pages) { should == 4 }
          end

          context 'per "String value that can not be converted into Number" (using default)' do
            subject { model_class.page(5).per('aho') }
            its(:total_pages) { should == 4 }
          end
        end


        describe '#current_page' do
          context 'page 1' do
            subject { model_class.page }
            its(:current_page) { should == 1 }
          end

          context 'page 2' do
            subject { model_class.page(2).per 3 }
            its(:current_page) { should == 2 }
          end
        end

        describe '#first_page?' do
          context 'on first page' do
            subject { model_class.page(1).per(10) }
            its(:first_page?) { should == true }
          end

          context 'not on first page' do
            subject { model_class.page(5).per(10) }
            its(:first_page?) { should == false }
          end
        end

        describe '#last_page?' do
          context 'on last page' do
            subject { model_class.page(10).per(10) }
            its(:last_page?) { should == true }
          end

          context 'not on last page' do
            subject { model_class.page(1).per(10) }
            its(:last_page?) { should == false }
          end
        end

        describe '#count' do
          context 'page 1' do
            subject { model_class.page }
            its(:count) { should == 25 }
          end

          context 'page 2' do
            subject { model_class.page 2 }
            its(:count) { should == 25 }
          end
        end

        context 'chained with .group' do
          subject { model_class.group('age').page(2).per 5 }
          # 0..10
          its(:total_count) { should == 11 }
          its(:total_pages) { should == 3 }
        end

        context 'activerecord descendants' do
          subject { ActiveRecord::Base.descendants }
          its(:length) { should_not == 0 }
        end
      end
    end
  end
end
