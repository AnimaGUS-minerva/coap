$:.unshift File.expand_path('lib', File.dirname(__FILE__))
require 'core/coap/version'

Gem::Specification.new do |s|
  s.name = 'coap'
  s.version = CoRE::CoAP::VERSION

  s.summary = 'Pure Ruby implementation of RFC 7252 (Constrained Application Protocol (CoAP))'
  s.description = 'Pure Ruby implementation of RFC 7252 (Constrained Application
    Protocol (CoAP)). The Constrained Application Protocol (CoAP) is a
    specialized web transfer protocol for use with constrained nodes and
    constrained (e.g., low-power, lossy) networks. The nodes often have 8-bit
    microcontrollers with small amounts of ROM and RAM, while constrained
    networks such as IPv6 over Low-Power Wireless Personal Area Networks
    (6LoWPANs) often have high packet error rates and a typical throughput of
    10s of kbit/s. The protocol is designed for machine-to-machine (M2M)
    applications such as smart energy and building automation.'

  s.homepage = 'https://github.com/nning/coap'
  s.license  = 'MIT'
  s.authors  = ['Carsten Bormann', 'Simon Frerichs', 'henning mueller']
  s.email    = 'henning@orgizm.net'

  s.files         = IO::read("all-files.txt").split($/)
  s.executables   = s.files.grep(%r{^bin/}) { |f| File.basename(f) }
  s.test_files    = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths = ['lib']

  s.add_development_dependency 'bundler',   '~> 1.6'
  s.add_development_dependency 'coveralls', '~> 0.7'
  s.add_development_dependency 'faker',     '~> 1.4'
  s.add_development_dependency 'minitest',  '~> 5.4'
  s.add_development_dependency 'rake',      '~> 10.3'
  s.add_development_dependency 'rspec',     '~> 3.0'

  s.add_dependency 'celluloid-io', '~> 0.17.3'
  s.add_dependency 'resolv-ipv6favor', '~> 0'
end
