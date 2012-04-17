module Rack
  module Formtastic
    class Samples
      def initialize(app)
        @app = app        
      end
      
      def call(env)
        @status, @headers, @body = @app.call(env)
        @env = env
  
        @body = '' if favicon?
        @body = static_file if !favicon? && static_file?
        @body = stylesheet if stylesheet?
        @headers ||= {}
        @headers['Content-Type'] = mime(extension)
        [@status, @headers, @body]
      end
      
      def static_file?
        !stylesheet?
      end
      
      def stylesheet?
        @env["PATH_INFO"] =~ /\.(css)/
      end
      
      def favicon?
        @env["PATH_INFO"] =~ /favicon.ico$/
      end
      
      def extension
        @env["PATH_INFO"].split(".").last
      end
      
      def mime(extension)
        mimes[extension] || mimes['html']
      end
      
      def mimes
        {
          'ico' => 'image/x-icon',
          'html' => 'text/html',
          'css' => 'text/css',
          'js' => 'text/javascript'
        }
      end
      
      def static_file
        ::File.open(file_path)
      end
      
      def stylesheet
        ::File.open(::File.join("../app/assets/stylesheets", file_path))
      end
      
      def file_path
        @env["PATH_INFO"].gsub(/^\//, '').gsub(/^$/, 'index.html')
      end
      
    end
  end
end

use Rack::ContentLength
use Rack::Formtastic::Samples

app = lambda { |env| [200, @headers, @body] }
run app
