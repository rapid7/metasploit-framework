shared_context 'profile' do
  def profile(name)
    formatted_time = Time.now.strftime('%Y%m%d%H%M%S')
    profile_pathname = Metasploit::Framework.root.join('spec', 'profiles', formatted_time, name)

    profile_pathname.parent.mkpath
    PerfTools::CpuProfiler.start(profile_pathname.to_path)

    yield

    PerfTools::CpuProfiler.stop
    puts "Generating pdf"
    pdf_pathname = "#{profile_pathname}.pdf"
    system("bundle exec pprof.rb --pdf #{profile_pathname} > #{pdf_pathname}")
    puts "PDF saved to #{pdf_pathname}"
    system("open #{pdf_pathname}")
  end
end
