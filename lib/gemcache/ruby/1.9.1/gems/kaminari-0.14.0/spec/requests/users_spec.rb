# encoding: UTF-8
require 'spec_helper'

feature 'Users' do
  background do
    1.upto(100) {|i| User.create! :name => "user#{'%03d' % i}" }
  end
  scenario 'navigating by pagination links' do
    visit '/users'

    within 'nav.pagination' do
      within 'span.page.current' do
        page.should have_content '1'
      end
      within 'span.next' do
        click_link 'Next ›'
      end
    end

    within 'nav.pagination' do
      within 'span.page.current' do
        page.should have_content '2'
      end
      within 'span.last' do
        click_link 'Last »'
      end
    end

    within 'nav.pagination' do
      within 'span.page.current' do
        page.should have_content '4'
      end
      within 'span.prev' do
        click_link '‹ Prev'
      end
    end

    within 'nav.pagination' do
      within 'span.page.current' do
        page.should have_content '3'
      end
      within 'span.first' do
        click_link '« First'
      end
    end

    within 'nav.pagination' do
      within 'span.page.current' do
        page.should have_content '1'
      end
    end
  end
end
