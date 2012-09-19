# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::Localizer' do
  describe "Cache" do
    before do
      @cache = Formtastic::Localizer::Cache.new
      @key = ['model', 'name']
      @undefined_key = ['model', 'undefined']
      @cache.set(@key, 'value')
    end
    
    it "should get value" do
      @cache.get(@key).should == 'value'
      @cache.get(@undefined_key).should be_nil
    end
    
    it "should check if key exists?" do
      @cache.has_key?(@key).should be_true
      @cache.has_key?(@undefined_key).should be_false
    end
    
    it "should set a key" do
      @cache.set(['model', 'name2'], 'value2')
      @cache.get(['model', 'name2']).should == 'value2'
    end
    
    it "should return hash" do
      @cache.cache.should be_an_instance_of(Hash)
    end
    
    it "should clear the cache" do
      @cache.clear!
      @cache.get(@key).should be_nil
    end
  end
  
  describe "Localizer" do
    include FormtasticSpecHelper      
    
    before do
      mock_everything    

      with_config :i18n_lookups_by_default, true do
        semantic_form_for(@new_post) do |builder|
          @localizer = Formtastic::Localizer.new(builder)
        end
      end
    end

    after do
      ::I18n.backend.reload!
    end
    
    it "should be defined" do
      lambda { Formtastic::Localizer }.should_not raise_error(::NameError)
    end
    
    it "should have a cache" do
      Formtastic::Localizer.cache.should be_an_instance_of(Formtastic::Localizer::Cache)
    end
    
    describe "localize" do
      def store_post_translations(value)
        ::I18n.backend.store_translations :en, {:formtastic => {
            :labels => {
              :post => { :name => value }
            }
          }
        }        
      end
      
      before do
        store_post_translations('POST.NAME')
      end

      it "should translate key with i18n" do
        @localizer.localize(:name, :name, :label).should == 'POST.NAME'
      end
      
      describe "with caching" do
        it "should not update translation when stored translations change" do
          with_config :i18n_cache_lookups, true do
            @localizer.localize(:name, :name, :label).should == 'POST.NAME'
            store_post_translations('POST.NEW_NAME')
            
            @localizer.localize(:name, :name, :label).should == 'POST.NAME'       
            
            Formtastic::Localizer.cache.clear!
            @localizer.localize(:name, :name, :label).should == 'POST.NEW_NAME'                  
          end
        end        
      end
      
      describe "without caching" do
        it "should update translation when stored translations change" do
          with_config :i18n_cache_lookups, false do
            @localizer.localize(:name, :name, :label).should == 'POST.NAME'
            store_post_translations('POST.NEW_NAME')
            @localizer.localize(:name, :name, :label).should == 'POST.NEW_NAME'            
          end
        end
      end
    end

  end

end