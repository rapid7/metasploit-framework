require 'spec_helper'

describe 'Kaminari::ActionViewExtension' do
  describe '#paginate' do
    before do
      50.times {|i| User.create! :name => "user#{i}"}
      @users = User.page(1)
    end
    subject { helper.paginate @users, :params => {:controller => 'users', :action => 'index'} }
    it { should be_a String }

    context 'escaping the pagination for javascript' do
      it 'should escape for javascript' do
        lambda { helper.escape_javascript(helper.paginate @users, :params => {:controller => 'users', :action => 'index'}) }.should_not raise_error
      end
    end
  end

  describe '#link_to_previous_page' do
    before do
      50.times {|i| User.create! :name => "user#{i}"}
    end
    context 'having previous pages' do
      before do
        @users = User.page(50)
      end
      context 'the default behaviour' do
        subject { helper.link_to_previous_page @users, 'Previous', :params => {:controller => 'users', :action => 'index'} }
        it { should be_a String }
        it { should match(/rel="previous"/) }
      end
      context 'overriding rel=' do
        subject { helper.link_to_previous_page @users, 'Previous', :rel => 'external', :params => {:controller => 'users', :action => 'index'} }
        it { should match(/rel="external"/) }
      end
    end
    context 'the first page' do
      before do
        @users = User.page(1)
      end
      subject { helper.link_to_previous_page @users, 'Previous', :params => {:controller => 'users', :action => 'index'} }
      it { should_not be }
    end
  end

  describe '#link_to_next_page' do
    before do
      50.times {|i| User.create! :name => "user#{i}"}
    end
    context 'having more page' do
      before do
        @users = User.page(1)
      end
      context 'the default behaviour' do
        subject { helper.link_to_next_page @users, 'More', :params => {:controller => 'users', :action => 'index'} }
        it { should be_a String }
        it { should match(/rel="next"/) }
      end
      context 'overriding rel=' do
        subject { helper.link_to_next_page @users, 'More', :rel => 'external', :params => {:controller => 'users', :action => 'index'} }
        it { should match(/rel="external"/) }
      end
    end
    context 'the last page' do
      before do
        @users = User.page(2)
      end
      subject { helper.link_to_next_page @users, 'More', :params => {:controller => 'users', :action => 'index'} }
      it { should_not be }
    end
  end

  describe '#page_entries_info' do
    context 'on a model without namespace' do
      before do
        @users = User.page(1).per(25)
      end
      context 'having no entries' do
        subject { helper.page_entries_info @users, :params => {:controller => 'users', :action => 'index'} }
        it      { should == 'No entries found' }

        context 'setting the entry name option to "member"' do
          subject { helper.page_entries_info @users, :entry_name => 'member', :params => {:controller => 'users', :action => 'index'} }
          it      { should == 'No members found' }
        end
      end

      context 'having 1 entry' do
        before do
          User.create! :name => 'user1'
          @users = User.page(1).per(25)
        end
        subject { helper.page_entries_info @users, :params => {:controller => 'users', :action => 'index'} }
        it      { should == 'Displaying <b>1</b> user' }

        context 'setting the entry name option to "member"' do
          subject { helper.page_entries_info @users, :entry_name => 'member', :params => {:controller => 'users', :action => 'index'} }
          it      { should == 'Displaying <b>1</b> member' }
        end
      end

      context 'having more than 1 but less than a page of entries' do
        before do
          10.times {|i| User.create! :name => "user#{i}"}
          @users = User.page(1).per(25)
        end
        subject { helper.page_entries_info @users, :params => {:controller => 'users', :action => 'index'} }
        it      { should == 'Displaying <b>all 10</b> users' }

        context 'setting the entry name option to "member"' do
          subject { helper.page_entries_info @users, :entry_name => 'member', :params => {:controller => 'users', :action => 'index'} }
          it      { should == 'Displaying <b>all 10</b> members' }
        end
      end

      context 'having more than one page of entries' do
        before do
          50.times {|i| User.create! :name => "user#{i}"}
        end

        describe 'the first page' do
          before do
            @users = User.page(1).per(25)
          end
          subject { helper.page_entries_info @users, :params => {:controller => 'users', :action => 'index'} }
          it      { should == 'Displaying users <b>1&nbsp;-&nbsp;25</b> of <b>50</b> in total' }

          context 'setting the entry name option to "member"' do
            subject { helper.page_entries_info @users, :entry_name => 'member', :params => {:controller => 'users', :action => 'index'} }
            it      { should == 'Displaying members <b>1&nbsp;-&nbsp;25</b> of <b>50</b> in total' }
          end
        end

        describe 'the next page' do
          before do
            @users = User.page(2).per(25)
          end
          subject { helper.page_entries_info @users, :params => {:controller => 'users', :action => 'index'} }
          it      { should == 'Displaying users <b>26&nbsp;-&nbsp;50</b> of <b>50</b> in total' }

          context 'setting the entry name option to "member"' do
            subject { helper.page_entries_info @users, :entry_name => 'member', :params => {:controller => 'users', :action => 'index'} }
            it      { should == 'Displaying members <b>26&nbsp;-&nbsp;50</b> of <b>50</b> in total' }
          end
        end
      end
    end
    context 'on a model with namespace' do
      before do
        @addresses = User::Address.page(1).per(25)
      end
      context 'having no entries' do
        subject { helper.page_entries_info @addresses, :params => {:controller => 'addresses', :action => 'index'} }
        it      { should == 'No entries found' }
      end

      context 'having 1 entry' do
        before do
          User::Address.create!
          @addresses = User::Address.page(1).per(25)
        end
        subject { helper.page_entries_info @addresses, :params => {:controller => 'addresses', :action => 'index'} }
        it      { should == 'Displaying <b>1</b> address' }

        context 'setting the entry name option to "place"' do
          subject { helper.page_entries_info @addresses, :entry_name => 'place', :params => {:controller => 'addresses', :action => 'index'} }
          it      { should == 'Displaying <b>1</b> place' }
        end
      end

      context 'having more than 1 but less than a page of entries' do
        before do
          10.times {|i| User::Address.create!}
          @addresses = User::Address.page(1).per(25)
        end
        subject { helper.page_entries_info @addresses, :params => {:controller => 'addresses', :action => 'index'} }
        it      { should == 'Displaying <b>all 10</b> addresses' }

        context 'setting the entry name option to "place"' do
          subject { helper.page_entries_info @addresses, :entry_name => 'place', :params => {:controller => 'addresses', :action => 'index'} }
          it      { should == 'Displaying <b>all 10</b> places' }
        end
      end

      context 'having more than one page of entries' do
        before do
          50.times {|i| User::Address.create!}
        end

        describe 'the first page' do
          before do
            @addresses = User::Address.page(1).per(25)
          end
          subject { helper.page_entries_info @addresses, :params => {:controller => 'addresses', :action => 'index'} }
          it      { should == 'Displaying addresses <b>1&nbsp;-&nbsp;25</b> of <b>50</b> in total' }

          context 'setting the entry name option to "place"' do
            subject { helper.page_entries_info @addresses, :entry_name => 'place', :params => {:controller => 'addresses', :action => 'index'} }
            it      { should == 'Displaying places <b>1&nbsp;-&nbsp;25</b> of <b>50</b> in total' }
          end
        end

        describe 'the next page' do
          before do
            @addresses = User::Address.page(2).per(25)
          end
          subject { helper.page_entries_info @addresses, :params => {:controller => 'addresses', :action => 'index'} }
          it      { should == 'Displaying addresses <b>26&nbsp;-&nbsp;50</b> of <b>50</b> in total' }

          context 'setting the entry name option to "place"' do
            subject { helper.page_entries_info @addresses, :entry_name => 'place', :params => {:controller => 'addresses', :action => 'index'} }
            it      { should == 'Displaying places <b>26&nbsp;-&nbsp;50</b> of <b>50</b> in total' }
          end
        end
      end
    end

    context 'on a PaginatableArray' do
      before do
        @numbers = Kaminari.paginate_array(%w{one two three}).page(1)
      end
      subject { helper.page_entries_info @numbers }
      it      { should == 'Displaying <b>all 3</b> entries' }
    end
  end

  describe '#rel_next_prev_link_tags' do
    before do
      75.times {|i| User.create! :name => "user#{i}"}
    end
    context 'the first page' do
      before do
        @users = User.page(1).per(25)
      end

      subject { helper.rel_next_prev_link_tags @users, :params => {:controller => 'users', :action => 'index'} }
      it { should be_a String }
      it { should match(/rel="next"/) }
      it { should_not match(/rel="prev"/) }
    end
    context 'the middle page' do
      before do
        @users = User.page(2).per(25)
      end

      subject { helper.rel_next_prev_link_tags @users, :params => {:controller => 'users', :action => 'index'} }
      it { should be_a String }
      it { should match(/rel="next"/) }
      it { should match(/rel="prev"/) }
    end
    context 'the last page' do
      before do
        @users = User.page(3).per(25)
      end

      subject { helper.rel_next_prev_link_tags @users, :params => {:controller => 'users', :action => 'index'} }
      it { should be_a String }
      it { should_not match(/rel="next"/) }
      it { should match(/rel="prev"/) }
    end
  end
end
