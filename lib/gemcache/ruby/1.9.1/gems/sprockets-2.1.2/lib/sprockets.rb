require 'sprockets/version'

module Sprockets
  # Environment
  autoload :Base,                    "sprockets/base"
  autoload :Engines,                 "sprockets/engines"
  autoload :Environment,             "sprockets/environment"
  autoload :Index,                   "sprockets/index"

  # Assets
  autoload :Asset,                   "sprockets/asset"
  autoload :BundledAsset,            "sprockets/bundled_asset"
  autoload :ProcessedAsset,          "sprockets/processed_asset"
  autoload :StaticAsset,             "sprockets/static_asset"

  # Processing
  autoload :CharsetNormalizer,       "sprockets/charset_normalizer"
  autoload :Context,                 "sprockets/context"
  autoload :DirectiveProcessor,      "sprockets/directive_processor"
  autoload :EcoTemplate,             "sprockets/eco_template"
  autoload :EjsTemplate,             "sprockets/ejs_template"
  autoload :JstProcessor,            "sprockets/jst_processor"
  autoload :Processor,               "sprockets/processor"
  autoload :SafetyColons,            "sprockets/safety_colons"

  # Internal utilities
  autoload :ArgumentError,           "sprockets/errors"
  autoload :AssetAttributes,         "sprockets/asset_attributes"
  autoload :CircularDependencyError, "sprockets/errors"
  autoload :ContentTypeMismatch,     "sprockets/errors"
  autoload :EngineError,             "sprockets/errors"
  autoload :Error,                   "sprockets/errors"
  autoload :FileNotFound,            "sprockets/errors"
  autoload :Utils,                   "sprockets/utils"

  module Cache
    autoload :FileStore, "sprockets/cache/file_store"
  end

  # Extend Sprockets module to provide global registry
  extend Engines
  @engines = {}

  # Cherry pick the default Tilt engines that make sense for
  # Sprockets. We don't need ones that only generate html like HAML.

  # Mmm, CoffeeScript
  register_engine '.coffee', Tilt::CoffeeScriptTemplate

  # JST engines
  register_engine '.jst',    JstProcessor
  register_engine '.eco',    EcoTemplate
  register_engine '.ejs',    EjsTemplate

  # CSS engines
  register_engine '.less',   Tilt::LessTemplate
  register_engine '.sass',   Tilt::SassTemplate
  register_engine '.scss',   Tilt::ScssTemplate

  # Other
  register_engine '.erb',    Tilt::ERBTemplate
  register_engine '.str',    Tilt::StringTemplate
end
