# Copyright (c) 2009-2013 VMware, Inc.
# Copyright (c) 2012 Piston Cloud Computing, Inc.

module Bosh::FifoCloud
  ##
  # Represents Fifo vip network: where users sets VM's IP (floating IP's
  # in Fifo)
  class VipNetwork < Network

    ##
    # Creates a new vip network
    #
    # @param [String] name Network name
    # @param [Hash] spec Raw network spec
    def initialize(name, spec)
      super
    end

    ##
    # Configures Fifo vip network
    #
    # @param [Fog::Compute::Fifo] fifo Fog Fifo Compute client
    # @param [Fog::Compute::Fifo::Server] server Fifo server to
    #   configure
    def configure(fifo, server)
      if @ip.nil?
        cloud_error("No IP provided for vip network `#{@name}'")
      end

      # Check if the Fifo floating IP is allocated. If true, disassociate
      # it from any server before associating it to the new server
      with_fifo do
        address = fifo.addresses.find { |a| a.ip == @ip }
        if address
          unless address.instance_id.nil?
            @logger.info("Disassociating floating IP `#{@ip}' " \
                         "from server `#{address.instance_id}'")
            address.server = nil
          end

          @logger.info("Associating server `#{server.id}' " \
                       "with floating IP `#{@ip}'")
          address.server = server
        else
          cloud_error("Floating IP #{@ip} not allocated")
        end
      end
    end

  end
end
