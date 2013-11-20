shared_context 'profile' do
  def profile(name)
    formatted_time = Time.now.strftime('%Y%m%d%H%M%S')
    profile_directory_pathname = Metasploit::Framework.root.join('spec', 'profiles', formatted_time)
    profile_directory_pathname.mkpath
    puts "Profile saving under #{profile_directory_pathname}"

    profile_pathname = profile_directory_pathname.join(name)
    PerfTools::CpuProfiler.start(profile_pathname.to_path)

    yield profile_directory_pathname

    PerfTools::CpuProfiler.stop
    puts "Generating pdf"
    pdf_pathname = "#{profile_pathname}.pdf"
    system("bundle exec pprof.rb --pdf #{profile_pathname} > #{pdf_pathname}")
    puts "PDF saved to #{pdf_pathname}"
    system("open #{pdf_pathname}")
  end
end
