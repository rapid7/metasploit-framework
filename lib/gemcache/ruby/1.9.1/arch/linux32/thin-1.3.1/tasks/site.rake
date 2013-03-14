namespace :site do
  task :build do
    mkdir_p 'tmp/site/images'
    cd 'tmp/site' do
      sh "SITE_ROOT='/thin' ruby ../../site/thin.rb --dump"
    end
    cp 'site/style.css', 'tmp/site'
    cp_r Dir['site/images/*'], 'tmp/site/images'
  end
  
  desc 'Upload website to code.macournoyer.com'
  task :upload => 'site:build' do
    upload 'tmp/site/*', 'thin'
  end
end
