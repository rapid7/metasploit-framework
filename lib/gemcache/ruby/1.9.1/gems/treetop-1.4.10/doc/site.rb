require 'rubygems'
require 'erector'
require "#{File.dirname(__FILE__)}/sitegen"
require 'fileutils'
require 'bluecloth'

class Layout < Erector::Widget
  def content
    html do
      head do
        link :rel => "stylesheet",
        :type => "text/css",
        :href => "./screen.css"
        
        rawtext %(
          <script src="http://www.google-analytics.com/urchin.js" type="text/javascript">
          </script>
          <script type="text/javascript">
          _uacct = "UA-3418876-1";
          urchinTracker();
          </script>
        )
      end

      body do
        div :id => 'top' do
          div :id => 'main_navigation' do
            main_navigation
          end
        end
        div :id => 'middle' do
          div :id => 'main_content' do
            main_content
          end
        end
        div :id => 'bottom' do

        end
      end
    end
  end

  def main_navigation
    ul do
      li { link_to "Documentation", SyntacticRecognition, Documentation }
      li { link_to "Contribute", Contribute }
      li { link_to "Home", Index }
    end
  end

  def main_content
  end
end

class Index < Layout
  def main_content
    bluecloth "index.markdown"
  end
end

class Documentation < Layout
  abstract

  def main_content
    div :id => 'secondary_navigation' do
      ul do
        li { link_to 'Syntax', SyntacticRecognition }
        li { link_to 'Semantics', SemanticInterpretation }
        li { link_to 'Using In Ruby', UsingInRuby }
        li { link_to 'Advanced Techniques', PitfallsAndAdvancedTechniques }
      end
    end
    
    div :id => 'documentation_content' do
      documentation_content
    end
  end
end

class SyntacticRecognition < Documentation
  def documentation_content
    bluecloth "syntactic_recognition.markdown"
  end
end

class SemanticInterpretation < Documentation
  def documentation_content
    bluecloth "semantic_interpretation.markdown"
  end
end

class UsingInRuby < Documentation
  def documentation_content
    bluecloth "using_in_ruby.markdown"
  end
end

class PitfallsAndAdvancedTechniques < Documentation
  def documentation_content
    bluecloth "pitfalls_and_advanced_techniques.markdown"
  end
end


class Contribute < Layout
  def main_content
    bluecloth "contributing_and_planned_features.markdown"
  end
end


Layout.generate_site