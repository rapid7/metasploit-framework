namespace :state_machine do
  desc 'Draws state machines using GraphViz (options: CLASS=User,Vehicle; FILE=user.rb,vehicle.rb [not required in Rails / Merb]; FONT=Arial; FORMAT=png; ORIENTATION=portrait; HUMAN_NAMES=true'
  task :draw do
    # Build drawing options
    options = {}
    options[:file] = ENV['FILE'] if ENV['FILE']
    options[:path] = ENV['TARGET'] if ENV['TARGET']
    options[:format] = ENV['FORMAT'] if ENV['FORMAT']
    options[:font] = ENV['FONT'] if ENV['FONT']
    options[:orientation] = ENV['ORIENTATION'] if ENV['ORIENTATION']
    options[:human_names] = ENV['HUMAN_NAMES'] == 'true' if ENV['HUMAN_NAMES']
    
    if defined?(Rails)
      puts "Files are automatically loaded in Rails; ignoring FILE option" if options.delete(:file)
      Rake::Task['environment'].invoke
    elsif defined?(Merb)
      puts "Files are automatically loaded in Merb; ignoring FILE option" if options.delete(:file)
      Rake::Task['merb_env'].invoke
      
      # Fix ruby-graphviz being incompatible with Merb's process title
      $0 = 'rake'
    else
      # Load the library
      $:.unshift(File.dirname(__FILE__) + '/..')
      require 'state_machine'
    end
    
    StateMachine::Machine.draw(ENV['CLASS'], options)
  end
end
