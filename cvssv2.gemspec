# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cvssv2/version'

Gem::Specification.new do |spec|
  spec.name          = "cvssv2"
  spec.version       = Cvssv2::VERSION
  spec.authors       = ["Victor Pereira"]
  spec.email         = ["vpereira@suse.de"]

  spec.summary       = %q{gem to parse cvssv2 vector}
  spec.description   = %q{gem to parse and score cvssv2 vectors}
  spec.homepage      = "https://github.com/vpereira/ruby-cvssv2"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest"
end
