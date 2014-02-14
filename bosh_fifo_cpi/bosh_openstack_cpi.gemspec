# coding: utf-8
require File.expand_path('../lib/cloud/fifo/version', __FILE__)

# Copyright (c) 2009-2013 VMware, Inc.
# Copyright (c) 2012 Piston Cloud Computing, Inc.

version = Bosh::FifoCloud::VERSION

Gem::Specification.new do |s|
  s.name        = 'bosh_fifo_cpi'
  s.version     = version
  s.platform    = Gem::Platform::RUBY
  s.summary     = 'BOSH Fifo CPI'
  s.description = "BOSH Fifo CPI\n#{`git rev-parse HEAD`[0, 6]}"
  s.author      = 'killfill'
  s.homepage    = 'https://github.com/cloudfoundry/bosh'
  s.license     = 'Apache 2.0'
  s.email       = 'project-fifo@googlegroups.com'
  s.required_ruby_version = Gem::Requirement.new('>= 1.9.3')

  s.files        = `git ls-files -- bin/* lib/*`.split("\n") + %w(README.md USAGE.md)
  s.require_path = 'lib'
  s.bindir       = 'bin'
  s.executables  = %w(bosh_fifo_console)

  s.add_dependency 'fog-fifo',      '~>0.1.0'
  s.add_dependency 'bosh_common',   "~>#{version}"
  s.add_dependency 'bosh_cpi',      "~>#{version}"
  s.add_dependency 'bosh-registry', "~>#{version}"
  s.add_dependency 'httpclient',    '=2.2.4'
  s.add_dependency 'yajl-ruby',     '>=0.8.2'
end
