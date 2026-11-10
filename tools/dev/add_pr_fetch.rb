#!/usr/bin/env ruby

%w[config config.worktree].each do |config_name|
  infile = `git rev-parse --git-path #{config_name}`.strip
  next unless File.file?(infile)

  $stderr.puts "Rewriting #{infile}"
  data = File.binread(infile)
  newdata = ""
  new_pr_line = false
  data.each_line do |line|
    newdata << line
    case line
    when /^(\s*)fetch\s*=.*remotes\/([^\/]+)\//
      ws = $1
      remote = $2
      pr_line = "fetch = +refs/pull/*/head:refs/remotes/#{remote}/pr/*"
      next if line.strip == pr_line.strip
      if data.include? pr_line
        $stderr.puts "Skipping #{remote}, already present"
        next
      else
        new_pr_line = true
        $stderr.puts "Adding pull request fetch for #{remote}"
        newdata << "#{ws}#{pr_line}\n"
      end
    end
  end

  if new_pr_line
    File.binwrite(infile, newdata)
    $stderr.puts "Wrote #{infile}"
  else
    $stderr.puts "No changes to #{infile}"
  end
end
