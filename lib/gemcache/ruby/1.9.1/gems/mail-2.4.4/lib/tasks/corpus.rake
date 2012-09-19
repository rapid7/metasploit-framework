namespace :corpus do

  task :load_mail do
    require File.expand_path('../../../spec/environment')
    require 'mail'
  end

  # Used to run parsing against an arbitrary corpus of email.
  # For example: http://plg.uwaterloo.ca/~gvcormac/treccorpus/
  desc "Provide a LOCATION=/some/dir to verify parsing in bulk, otherwise defaults"
  task :verify_all => :load_mail do

    root_of_corpus    = ENV['LOCATION'] || 'corpus/spam'
    @save_failures_to = ENV['SAVE_TO']  || 'spec/fixtures/emails/failed_emails'
    @failed_emails    = []
    @checked_count    = 0

    if root_of_corpus
      root_of_corpus = File.expand_path(root_of_corpus)
      if not File.directory?(root_of_corpus)
        raise "\n\tPath '#{root_of_corpus}' is not a directory.\n\n"
      end
    else
      raise "\n\tSupply path to corpus: LOCATION=/path/to/corpus\n\n"
    end

    if @save_failures_to
      if not File.directory?(@save_failures_to)
        raise "\n\tPath '#{@save_failures_to}' is not a directory.\n\n"
      end
      @save_failures_to = File.expand_path(@save_failures_to)
      puts "Mail which fails to parse will be saved in '#{@save_failures_to}'"
    end

    puts "Checking '#{root_of_corpus}' directory (recursively)"

    # we're tracking all the errors separately, don't clutter terminal
    $stderr_backup = $stderr.dup
    $stderr.reopen("/dev/null", "w")
    STDERR = $stderr

    dir_node(root_of_corpus)

    # put our toys back now that we're done with them
    $stderr = $stderr_backup.dup
    STDERR = $stderr

    puts "\n\n"
        
    if @failed_emails.any?
      report_failures_to_stdout
    end
    puts "Out of Total: #{@checked_count}"

    if @save_failures_to
      puts "Add SAVE_TO=/some/dir to save failed emails to for review.,"
      puts "May result in a lot of saved files. Do a dry run first!\n\n"
    else
      puts "There are no errors"
    end
  end

  def dir_node(path)
    puts "\n\n"
    puts "Checking emails in '#{path}':"

    entries = Dir.entries(path)

    entries.each do |entry|
      next if ['.', '..'].include?(entry)
      full_path = File.join(path, entry)

      if File.file?(full_path)
        file_node(full_path)
      elsif File.directory?(full_path)
        dir_node(full_path)
      end
    end
  end
  
  def file_node(path)
    verify(path)
  end
  
  def verify(path)
    result, message = parse_as_mail(path)
    if result
      print '.'
      $stdout.flush
    else
      save_failure(path, message)
      print 'x'
    end
  end

  def save_failure(path, message)
    @failed_emails << [path, message]
    if @save_failures_to
      email_basename = File.basename(path)
      failure_as_filename = message.gsub(/\W/, '_')
      new_email_name = [failure_as_filename, email_basename].join("_")
      File.open(File.join(@save_failures_to, new_email_name), 'w+') do |fh|
        fh << File.read(path)
      end 
    end
  end

  def parse_as_mail(path)
    @checked_count += 1
    begin
      parsed_mail = Mail.read(path)
      [true, nil]
    rescue => e
      [false, e.message]
    end
  end
  
  def report_failures_to_stdout
    @failed_emails.each do |failed|
      puts "#{failed[0]} : #{failed[1]}"
    end
    puts "Failed: #{@failed_emails.size}"
  end
  
end
