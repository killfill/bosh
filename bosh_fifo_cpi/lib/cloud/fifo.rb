# Copyright (c) 2009-2013 VMware, Inc.
# Copyright (c) 2012 Piston Cloud Computing, Inc.

module Bosh
  module FifoCloud; end
end

require "fog"
require "fog/fifo"
require "httpclient"
require "json"
require "pp"
require "set"
require "tmpdir"
require "securerandom"
require "yajl"

require "common/exec"
require "common/thread_pool"
require "common/thread_formatter"

require 'bosh/registry/client'
require "cloud"
require "cloud/fifo/helpers"
require "cloud/fifo/cloud"
require "cloud/fifo/tag_manager"
require "cloud/fifo/version"

require "cloud/fifo/network_configurator"
require "cloud/fifo/network"
require "cloud/fifo/dynamic_network"
require "cloud/fifo/manual_network"
require "cloud/fifo/vip_network"

module Bosh
  module Clouds
    Fifo = Bosh::FifoCloud::Cloud
  end
end
