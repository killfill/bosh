# Copyright (c) 2009-2012 VMware, Inc.

module Bosh::Deployer
  class InstanceManager
    class Dummy < InstanceManager
      def remote_tunnel(port)
      end

      def disk_model
        nil
      end

      def update_spec(spec)
        properties = spec.properties

        properties['dummy'] =
          Config.spec_properties['dummy'] ||
          Config.cloud_options['properties']['dummy'].dup

        properties['dummy']['address'] ||= properties['dummy']['host']
      end

      def check_dependencies
      end

      def start
      end

      def stop
      end

      def discover_bosh_ip
        bosh_ip
      end

      def service_ip
        bosh_ip
      end

      # @return [Integer] size in MiB
      def disk_size(cid)
        return 123*1024*1024
      end

      def persistent_disk_changed?
        false
      end

      private

      FakeRegistry = Struct.new(:port)
      def registry
        @registry ||= FakeRegistry.new(nil)
      end
    end
  end
end
