# Copyright (c) 2009-2013 VMware, Inc.
# Copyright (c) 2012 Piston Cloud Computing, Inc.

module Bosh::FifoCloud
  ##
  # Represents Fifo dynamic network: where IaaS sets VM's IP
  class DynamicNetwork < Network

    ##
    # Creates a new dynamic network
    #
    # @param [String] name Network name
    # @param [Hash] spec Raw network spec
    def initialize(name, spec)
      super
    end

    ##
    # Configures Fifo dynamic network. Right now it's a no-op,
    # as dynamic networks are completely managed by Fifo
    #
    # @param [Fog::Compute::Fifo] fifo Fog Fifo Compute client
    # @param [Fog::Compute::Fifo::Server] server Fifo server to
    #   configure
    def configure(fifo, server)
    end

  end
end
