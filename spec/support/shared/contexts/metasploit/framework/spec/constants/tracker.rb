shared_examples_for 'Metasploit::Framework::Spec::Constants tracker' do
  around(:each) do |example|
    example.run

    count = Metasploit::Framework::Spec::Constants.each { |parent_constant, child_name|
      $stderr.puts "#{child_name} was not removed from #{parent_constant}"
    }

    if count > 0
      $stderr.puts "Use `include_context 'Metasploit::Framework::Spec::Constants cleaner'` to clean up constants from #{example.metadata.full_description}"
    end

    if defined? Msf::Modules
      inherit = false
      constants = Msf::Modules.constants(inherit)

      constants.each do |constant|
        $stderr.puts "#{constant} not removed from Msf::Modules."
      end

      unless constants.empty?
      end
    end
  end
end