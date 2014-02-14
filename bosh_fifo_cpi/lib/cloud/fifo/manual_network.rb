# Copyright (c) 2009-2013 VMware, Inc.

module Bosh::FifoCloud
  ##
  # Represents Fifo manual network: where user sets VM's IP
  class ManualNetwork < Network

    ##
    # Creates a new manual network
    #
    # @param [String] name Network name
    # @param [Hash] spec Raw network spec
    def initialize(name, spec)
      super
    end

    ##
    # Returns the private IP address
    #
    # @return [String] ip address
    def private_ip
      @ip
    end

    ##
    # Configures Fifo manual network. Right now it's a no-op,
    # as manual networks are completely managed by Fifo
    #
    # @param [Fog::Compute::Fifo] fifo Fog Fifo Compute client
    # @param [Fog::Compute::Fifo::Server] server Fifo server to
    #   configure
    def configure(fifo, server)
    end
  end
end
