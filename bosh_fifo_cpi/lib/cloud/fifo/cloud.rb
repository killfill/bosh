# Copyright (c) 2009-2013 VMware, Inc.
# Copyright (c) 2012 Piston Cloud Computing, Inc.

module Bosh::FifoCloud
  ##
  # BOSH Fifo CPI
  class Cloud < Bosh::Cloud
    include Helpers

    BOSH_APP_DIR = "/var/vcap/bosh"
    FIRST_DEVICE_NAME_LETTER = "b"

    attr_reader :fifo
    attr_reader :registry
    attr_reader :glance
    attr_accessor :logger

    ##
    # Creates a new BOSH Fifo CPI
    #
    # @param [Hash] options CPI options
    # @option options [Hash] fifo Fifo specific options
    # @option options [Hash] agent agent options
    # @option options [Hash] registry agent options
    def initialize(options)
      @options = options.dup

      validate_options
      initialize_registry

      @logger = Bosh::Clouds::Config.logger

      @agent_properties = @options["agent"] || {}
      @fifo_properties = @options["fifo"]

      @default_key_name = @fifo_properties["default_key_name"]
      @default_security_groups = @fifo_properties["default_security_groups"]
      @state_timeout = @fifo_properties["state_timeout"]
      @stemcell_public_visibility = @fifo_properties["stemcell_public_visibility"]

      # unless @fifo_properties["auth_url"].match(/\/tokens$/)
      #   @fifo_properties["auth_url"] = @fifo_properties["auth_url"] + "/tokens"
      # end

      fifo_params = {
        :provider => "Fifo",
        :fifo_url => @fifo_properties["url"],
        :fifo_username => @fifo_properties["username"],
        :fifo_password => @fifo_properties["password"]
      }
      begin
        @fifo = Fog::Compute.new(fifo_params)
      rescue Exception => e
        @logger.error(e)
        cloud_error("Unable to connect to the Fifo Compute API. Check task debug log for details.")  
      end

      # glance_params = {
      #   :provider => "Fifo",
      #   :fifo_auth_url => @fifo_properties["auth_url"],
      #   :fifo_username => @fifo_properties["username"],
      #   :fifo_api_key => @fifo_properties["api_key"],
      #   :fifo_tenant => @fifo_properties["tenant"],
      #   :fifo_region => @fifo_properties["region"],
      #   :fifo_endpoint_type => @fifo_properties["endpoint_type"],
      #   :connection_options => @fifo_properties['connection_options']
      # }
      # begin
      #   @glance = Fog::Image.new(glance_params)
      # rescue Exception => e
      #   @logger.error(e)
      #   cloud_error("Unable to connect to the Fifo Image Service API. Check task debug log for details.")
      # end

      @metadata_lock = Mutex.new
    end

    ##
    # Creates a new Fifo Image using stemcell image. It requires access
    # to the Fifo Glance service.
    #
    # @param [String] image_path Local filesystem path to a stemcell image
    # @param [Hash] cloud_properties CPI-specific properties
    # @option cloud_properties [String] name Stemcell name
    # @option cloud_properties [String] version Stemcell version
    # @option cloud_properties [String] infrastructure Stemcell infraestructure
    # @option cloud_properties [String] disk_format Image disk format
    # @option cloud_properties [String] container_format Image container format
    # @option cloud_properties [optional, String] kernel_file Name of the
    #   kernel image file provided at the stemcell archive
    # @option cloud_properties [optional, String] ramdisk_file Name of the
    #   ramdisk image file provided at the stemcell archive
    # @return [String] Fifo image UUID of the stemcell
    def create_stemcell(image_path, cloud_properties)
      with_thread_name("create_stemcell(#{image_path}...)") do
        begin
          Dir.mktmpdir do |tmp_dir|
            @logger.info("Creating new image...")
            image_params = {
              :name => "BOSH-#{generate_unique_name}",
              :disk_format => cloud_properties["disk_format"],
              :container_format => cloud_properties["container_format"],
              :is_public => @stemcell_public_visibility.nil? ? false : @stemcell_public_visibility,
            }
            
            image_properties = {}
            vanilla_options = ["name", "version", "os_type", "os_distro", "architecture", "auto_disk_config"]
            vanilla_options.reject{ |o| cloud_properties[o].nil? }.each do |key|
              image_properties[key.to_sym] = cloud_properties[key]
            end            
            image_params[:properties] = image_properties unless image_properties.empty?
            
            # If image_location is set in cloud properties, then pass the copy-from parm. Then Glance will fetch it 
            # from the remote location on a background job and store it in its repository.
            # Otherwise, unpack image to temp directory and upload to Glance the root image.
            if cloud_properties["image_location"]
              @logger.info("Using remote image from `#{cloud_properties["image_location"]}'...")
              image_params[:copy_from] = cloud_properties["image_location"]
            else
              @logger.info("Extracting stemcell file to `#{tmp_dir}'...")
              unpack_image(tmp_dir, image_path)
              image_params[:location] = File.join(tmp_dir, "root.img")
            end

            # Upload image using Glance service            
            @logger.debug("Using image parms: `#{image_params.inspect}'")
            image = with_fifo { @glance.images.create(image_params) }
            
            @logger.info("Creating new image `#{image.id}'...")
            wait_resource(image, :active)
            
            image.id.to_s
          end
        rescue => e
          @logger.error(e)
          raise e
        end
      end
    end

    ##
    # Deletes a stemcell
    #
    # @param [String] stemcell_id Fifo image UUID of the stemcell to be
    #   deleted
    # @return [void]
    def delete_stemcell(stemcell_id)
      with_thread_name("delete_stemcell(#{stemcell_id})") do
        @logger.info("Deleting stemcell `#{stemcell_id}'...")
        image = with_fifo { @glance.images.find_by_id(stemcell_id) }
        if image
          with_fifo { image.destroy }
          @logger.info("Stemcell `#{stemcell_id}' is now deleted")
        else
          @logger.info("Stemcell `#{stemcell_id}' not found. Skipping.")
        end
      end
    end

    ##
    # Creates an Fifo server and waits until it's in running state
    #
    # @param [String] agent_id UUID for the agent that will be used later on by
    #   the director to locate and talk to the agent
    # @param [String] stemcell_id Fifo image UUID that will be used to
    #   power on new server
    # @param [Hash] resource_pool cloud specific properties describing the
    #   resources needed for this VM
    # @param [Hash] networks list of networks and their settings needed for
    #   this VM
    # @param [optional, Array] disk_locality List of disks that might be
    #   attached to this server in the future, can be used as a placement
    #   hint (i.e. server will only be created if resource pool availability
    #   zone is the same as disk availability zone)
    # @param [optional, Hash] environment Data to be merged into agent settings
    # @return [String] Fifo server UUID
    def create_vm(agent_id, stemcell_id, resource_pool,
                  network_spec = nil, disk_locality = nil, environment = nil)
      with_thread_name("create_vm(#{agent_id}, ...)") do
        @logger.info("Creating new server...")
        server_name = "vm-#{generate_unique_name}"



        #USO:
        #killfill@aire:~/Public/bosh [fifo_cpi] $ ./bin/bosh_fifo_console -c ../bosh-mio/deployments/microbosh-fifo/console.yml
        #cpi.create_vm('asd', 'd2ba0f30-bbe8-11e2-a9a2-6bc116856d85', {'instance_type'=>'f8a2918f-1cd2-4950-8ea3-0ee341426fac'}, '8d4d8b0a-e726-4b52-9c5c-0d8a41221ff2')


        # network_configurator = NetworkConfigurator.new(network_spec)

        # fifo_security_groups = with_fifo { @fifo.security_groups }.collect { |sg| sg.name }
        # security_groups = network_configurator.security_groups(@default_security_groups)
        # security_groups.each do |sg|
        #   cloud_error("Security group `#{sg}' not found") unless fifo_security_groups.include?(sg)
        # end
        # @logger.debug("Using security groups: `#{security_groups.join(', ')}'")

        # nics = network_configurator.nics
        # @logger.debug("Using NICs: `#{nics.join(', ')}'")

        net = @fifo.networks.get(network_spec)
        @logger.debug("Using network: `#{net.name}'")

        image = with_fifo { @fifo.datasets.get(stemcell_id) }
        cloud_error("Image `#{stemcell_id}' not found") if image.nil?
        @logger.debug("Using image: `#{image.name} v#{image.version}'")

        flavor = with_fifo { @fifo.packages.get(resource_pool["instance_type"]) }
        cloud_error("Flavor `#{resource_pool["instance_type"]}' not found") if flavor.nil?
        # if flavor_has_ephemeral_disk?(flavor)
        #   if flavor.ram
        #     # Ephemeral disk size should be at least the double of the vm total memory size, as agent will need:
        #     # - vm total memory size for swapon,
        #     # - the rest for /vcar/vcap/data
        #     min_ephemeral_size = (flavor.ram / 1024) * 2
        #     if flavor.ephemeral < min_ephemeral_size
        #       cloud_error("Flavor `#{resource_pool["instance_type"]}' should have at least #{min_ephemeral_size}Gb " +
        #                   "of ephemeral disk")
        #     end
        #   end
        # end
        @logger.debug("Using flavor: `#{flavor.name} [#{flavor.ram}MB, #{flavor.cpu_cap}CAP, #{flavor.quota}GB]'")

        keyname = resource_pool["key_name"] || @default_key_name
        # keypair = with_fifo { @fifo.key_pairs.find { |k| k.name == keyname } }
        # cloud_error("Key-pair `#{keyname}' not found") if keypair.nil?
        # @logger.debug("Using key-pair: `#{keypair.name}' (#{keypair.fingerprint})")

        server_params = {
          :config => {
            :alias => server_name,
            :networks => {
              :net0 => network_spec
            }
          },
          :package => flavor.uuid,
          :dataset => image.dataset,
          :user_data => Yajl::Encoder.encode(user_data(server_name, {})),
          :personality => [{
                            "path" => "#{BOSH_APP_DIR}/user_data.json",
                            #"contents" => Yajl::Encoder.encode(user_data(server_name, network_spec, keypair.public_key))
                          }]
        }

        # availability_zone = select_availability_zone(disk_locality, resource_pool["availability_zone"])
        # server_params[:availability_zone] = availability_zone if availability_zone

        @logger.debug("Using boot parms: `#{server_params.inspect}'")
        server = with_fifo { @fifo.servers.create(server_params) }

        @logger.info("Creating new server `#{server.uuid}'...")
        begin
          wait_resource(server, :running, :state)
        rescue Bosh::Clouds::CloudError => e
          @logger.warn("Failed to create server: #{e.message}. Log: #{server.log.collect{|l| l['log']}.join(', ')}")

          with_fifo { server.delete }

          raise Bosh::Clouds::VMCreationFailed.new(true)
        end

        # @logger.info("Configuring network for server `#{server.id}'...")
        # network_configurator.configure(@fifo, server)

        @logger.info("Updating settings for server `#{server.uuid}'...")

        @logger.warn("This registriy thingy looks important need to implement it.!!!!!!!")

        # settings = initial_agent_settings(server_name, agent_id, network_spec, environment,
                                          # flavor_has_ephemeral_disk?(flavor))
        # @registry.update_settings(server.name, settings)

        server.uuid
      end
    end

    ##
    # Terminates an Fifo server and waits until it reports as terminated
    #
    # @param [String] server_id Fifo server UUID
    # @return [void]
    def delete_vm(server_id)
      with_thread_name("delete_vm(#{server_id})") do
        @logger.info("Deleting server `#{server_id}'...")
        server = with_fifo { @fifo.servers.get(server_id) }
        if server
          with_fifo { server.delete }

          @logger.info("Deleting settings for server `#{server.uuid}'...")
          @logger.warn("This registriy thingy looks important need to implement it.!!!!!!!")
          # @registry.delete_settings(server.name)
        else
          @logger.info("Server `#{server_id}' not found. Skipping.")
        end
      end
    end

    ##
    # Checks if an Fifo server exists
    #
    # @param [String] server_id Fifo server UUID
    # @return [Boolean] True if the vm exists
    def has_vm?(server_id)
      with_thread_name("has_vm?(#{server_id})") do
        begin 
          server = with_fifo { @fifo.servers.get(server_id) }
          return true
        rescue
          return false
        end
      end
    end

    ##
    # Reboots an Fifo Server
    #
    # @param [String] server_id Fifo server UUID
    # @return [void]
    def reboot_vm(server_id)
      with_thread_name("reboot_vm(#{server_id})") do
        server = with_fifo { @fifo.servers.get(server_id) }

        soft_reboot(server)
      end
    end

    ##
    # Configures networking on existing Fifo server
    #
    # @param [String] server_id Fifo server UUID
    # @param [Hash] network_spec Raw network spec passed by director
    # @return [void]
    # @raise [Bosh::Clouds:NotSupported] If there's a network change that requires the recreation of the VM
    def configure_networks(server_id, network_spec)
      with_thread_name("configure_networks(#{server_id}, ...)") do
        @logger.info("Configuring `#{server_id}' to use the following " \
                     "network settings: #{network_spec.pretty_inspect}")
        network_configurator = NetworkConfigurator.new(network_spec)

        server = with_fifo { @fifo.servers.get(server_id) }
        cloud_error("Server `#{server_id}' not found") unless server

        compare_security_groups(server, network_configurator.security_groups(@default_security_groups))

        compare_private_ip_addresses(server, network_configurator.private_ip)
        
        network_configurator.configure(@fifo, server)

        update_agent_settings(server) do |settings|
          settings["networks"] = network_spec
        end
      end
    end

    ##
    # Creates a new Fifo volume
    #
    # @param [Integer] size disk size in MiB
    # @param [optional, String] server_id Fifo server UUID of the VM that
    #   this disk will be attached to
    # @return [String] Fifo volume UUID
    def create_disk(size, server_id = nil)
      with_thread_name("create_disk(#{size}, #{server_id})") do
        raise ArgumentError, "Disk size needs to be an integer" unless size.kind_of?(Integer)
        cloud_error("Minimum disk size is 1 GiB") if (size < 1024)
        cloud_error("Maximum disk size is 1 TiB") if (size > 1024 * 1000)

        volume_params = {
          :name => "volume-#{generate_unique_name}",
          :description => "",
          :size => (size / 1024.0).ceil
        }

        if server_id
          server = with_fifo { @fifo.servers.get(server_id) }
          if server && server.availability_zone
            volume_params[:availability_zone] = server.availability_zone
          end
        end

        @logger.info("Creating new volume...")
        volume = with_fifo { @fifo.volumes.create(volume_params) }

        @logger.info("Creating new volume `#{volume.id}'...")
        wait_resource(volume, :available)

        volume.id.to_s
      end
    end

    ##
    # Deletes an Fifo volume
    #
    # @param [String] disk_id Fifo volume UUID
    # @return [void]
    # @raise [Bosh::Clouds::CloudError] if disk is not in available state
    def delete_disk(disk_id)
      with_thread_name("delete_disk(#{disk_id})") do
        @logger.info("Deleting volume `#{disk_id}'...")
        volume = with_fifo { @fifo.volumes.get(disk_id) }
        if volume
          state = volume.status
          if state.to_sym != :available
            cloud_error("Cannot delete volume `#{disk_id}', state is #{state}")
          end

          with_fifo { volume.destroy }
          wait_resource(volume, :deleted, :status, true)
        else
          @logger.info("Volume `#{disk_id}' not found. Skipping.")
        end
      end
    end

    ##
    # Attaches an Fifo volume to an Fifo server
    #
    # @param [String] server_id Fifo server UUID
    # @param [String] disk_id Fifo volume UUID
    # @return [void]
    def attach_disk(server_id, disk_id)
      with_thread_name("attach_disk(#{server_id}, #{disk_id})") do
        server = with_fifo { @fifo.servers.get(server_id) }
        cloud_error("Server `#{server_id}' not found") unless server

        volume = with_fifo { @fifo.volumes.get(disk_id) }
        cloud_error("Volume `#{disk_id}' not found") unless volume

        device_name = attach_volume(server, volume)

        update_agent_settings(server) do |settings|
          settings["disks"] ||= {}
          settings["disks"]["persistent"] ||= {}
          settings["disks"]["persistent"][disk_id] = device_name
        end
      end
    end

    ##
    # Detaches an Fifo volume from an Fifo server
    #
    # @param [String] server_id Fifo server UUID
    # @param [String] disk_id Fifo volume UUID
    # @return [void]
    def detach_disk(server_id, disk_id)
      with_thread_name("detach_disk(#{server_id}, #{disk_id})") do
        server = with_fifo { @fifo.servers.get(server_id) }
        cloud_error("Server `#{server_id}' not found") unless server

        volume = with_fifo { @fifo.volumes.get(disk_id) }
        cloud_error("Volume `#{disk_id}' not found") unless volume

        detach_volume(server, volume)

        update_agent_settings(server) do |settings|
          settings["disks"] ||= {}
          settings["disks"]["persistent"] ||= {}
          settings["disks"]["persistent"].delete(disk_id)
        end
      end
    end

    ##
    # Takes a snapshot of an Fifo volume
    #
    # @param [String] disk_id Fifo volume UUID
    # @param [Hash] metadata Metadata key/value pairs to add to snapshot
    # @return [String] Fifo snapshot UUID
    # @raise [Bosh::Clouds::CloudError] if volume is not found
    def snapshot_disk(disk_id, metadata)
      with_thread_name("snapshot_disk(#{disk_id})") do
        volume = with_fifo { @fifo.volumes.get(disk_id) }
        cloud_error("Volume `#{disk_id}' not found") unless volume

        devices = []
        volume.attachments.each { |attachment| devices << attachment["device"] unless attachment.empty? }
       
        description = [:deployment, :job, :index].collect { |key| metadata[key] }
        description << devices.first.split('/').last unless devices.empty?
        snapshot_params = {
          :name => "snapshot-#{generate_unique_name}",
          :description => description.join('/'),
          :volume_id => volume.id
        }

        @logger.info("Creating new snapshot for volume `#{disk_id}'...")
        snapshot = @fifo.snapshots.new(snapshot_params)
        with_fifo { snapshot.save(true) }

        @logger.info("Creating new snapshot `#{snapshot.id}' for volume `#{disk_id}'...")
        wait_resource(snapshot, :available)

        snapshot.id.to_s
      end
    end

    ##
    # Deletes an Fifo volume snapshot
    #
    # @param [String] snapshot_id Fifo snapshot UUID
    # @return [void]
    # @raise [Bosh::Clouds::CloudError] if snapshot is not in available state
    def delete_snapshot(snapshot_id)
      with_thread_name("delete_snapshot(#{snapshot_id})") do
        @logger.info("Deleting snapshot `#{snapshot_id}'...")
        snapshot = with_fifo { @fifo.snapshots.get(snapshot_id) }
        if snapshot
          state = snapshot.status
          if state.to_sym != :available
            cloud_error("Cannot delete snapshot `#{snapshot_id}', state is #{state}")
          end

          with_fifo { snapshot.destroy }
          wait_resource(snapshot, :deleted, :status, true)
        else
          @logger.info("Snapshot `#{snapshot_id}' not found. Skipping.")
        end
      end
    end

    ##
    # Set metadata for an Fifo server
    #
    # @param [String] server_id Fifo server UUID
    # @param [Hash] metadata Metadata key/value pairs
    # @return [void]
    def set_vm_metadata(server_id, metadata)
      with_thread_name("set_vm_metadata(#{server_id}, ...)") do
        with_fifo do
          server = @fifo.servers.get(server_id)
          cloud_error("Server `#{server_id}' not found") unless server

          metadata.each do |name, value|
            TagManager.tag(server, name, value)
          end
        end
      end
    end

    ##
    # Validates the deployment
    #
    # @note Not implemented in the Fifo CPI
    def validate_deployment(old_manifest, new_manifest)
      not_implemented(:validate_deployment)
    end

    ##
    # Selects the availability zone to use from a list of disk volumes,
    # resource pool availability zone (if any) and the default availability
    # zone.
    #
    # @param [Array] volumes Fifo volume UUIDs to attach to the vm
    # @param [String] resource_pool_az availability zone specified in
    #   the resource pool (may be nil)
    # @return [String] availability zone to use or nil
    # @note this is a private method that is public to make it easier to test
    def select_availability_zone(volumes, resource_pool_az)
      if volumes && !volumes.empty?
        disks = volumes.map { |vid| with_fifo { @fifo.volumes.get(vid) } }
        ensure_same_availability_zone(disks, resource_pool_az)
        disks.first.availability_zone
      else
        resource_pool_az
      end
    end

    ##
    # Ensure all supplied availability zones are the same
    #
    # @param [Array] disks Fifo volumes
    # @param [String] default availability zone specified in
    #   the resource pool (may be nil)
    # @return [String] availability zone to use or nil
    # @note this is a private method that is public to make it easier to test
    def ensure_same_availability_zone(disks, default)
      zones = disks.map { |disk| disk.availability_zone }
      zones << default if default
      zones.uniq!
      cloud_error "can't use multiple availability zones: %s" %
        zones.join(", ") unless zones.size == 1 || zones.empty?
    end

    private

    ##
    # Generates an unique name
    #
    # @return [String] Unique name
    def generate_unique_name
      SecureRandom.uuid
    end

    ##
    # Prepare server user data
    #
    # @param [String] server_name server name
    # @param [Hash] network_spec network specification
    # @return [Hash] server user data
    def user_data(server_name, network_spec, public_key = nil)
      data = {}

      data["registry"] = { "endpoint" => @registry.endpoint }
      data["server"] = { "name" => server_name }
      data["openssh"] = { "public_key" => public_key } if public_key

      with_dns(network_spec) do |servers|
        data["dns"] = { "nameserver" => servers }
      end

      data
    end

    ##
    # Extract dns server list from network spec and yield the the list
    #
    # @param [Hash] network_spec network specification for instance
    # @yield [Array]
    def with_dns(network_spec)
      network_spec.each_value do |properties|
        if properties.has_key?("dns") && !properties["dns"].nil?
          yield properties["dns"]
          return
        end
      end
    end

    ##
    # Generates initial agent settings. These settings will be read by Bosh Agent from Bosh Registry on a target 
    # server. Disk conventions in Bosh Agent for Fifo are:
    # - system disk: /dev/sda
    # - ephemeral disk: /dev/sdb
    # - persistent disks: /dev/sdc through /dev/sdz
    # As some kernels remap device names (from sd* to vd* or xvd*), Bosh Agent will lookup for the proper device name 
    #
    # @param [String] server_name Name of the Fifo server (will be picked
    #   up by agent to fetch registry settings)
    # @param [String] agent_id Agent id (will be picked up by agent to
    #   assume its identity
    # @param [Hash] network_spec Agent network spec
    # @param [Hash] environment Environment settings
    # @param [Boolean] has_ephemeral Has Ephemeral disk?
    # @return [Hash] Agent settings
    def initial_agent_settings(server_name, agent_id, network_spec, environment, has_ephemeral)
      settings = {
        "vm" => {
          "name" => server_name
        },
        "agent_id" => agent_id,
        "networks" => network_spec,
        "disks" => {
          "system" => "/dev/sda",
          "persistent" => {}
        }
      }

      settings["disks"]["ephemeral"] = has_ephemeral ? "/dev/sdb" : nil
      settings["env"] = environment if environment
      settings.merge(@agent_properties)
    end

    ##
    # Updates the agent settings
    #
    # @param [Fog::Compute::Fifo::Server] server Fifo server
    def update_agent_settings(server)
      raise ArgumentError, "Block is not provided" unless block_given?

      @logger.info("Updating settings for server `#{server.uuid}'...")
      settings = @registry.read_settings(server.name)
      yield settings
      @registry.update_settings(server.name, settings)
    end

    ##
    # Soft reboots an Fifo server
    #
    # @param [Fog::Compute::Fifo::Server] server Fifo server
    # @return [void]
    def soft_reboot(server)
      @logger.info("Soft rebooting server `#{server.uuid}'...")
      with_fifo { server.reboot }
      wait_resource(server, :running, :state)
    end

    ##
    # Hard reboots an Fifo server
    #
    # @param [Fog::Compute::Fifo::Server] server Fifo server
    # @return [void]
    def hard_reboot(server)
      @logger.info("Hard rebooting server `#{server.uuid}'...")
      with_fifo { server.reboot(type = 'HARD') }
      wait_resource(server, :running, :state)
    end

    ##
    # Attaches an Fifo volume to an Fifo server
    #
    # @param [Fog::Compute::Fifo::Server] server Fifo server
    # @param [Fog::Compute::Fifo::Volume] volume Fifo volume
    # @return [String] Device name
    def attach_volume(server, volume)
      @logger.info("Attaching volume `#{volume.id}' to server `#{server.id}'...")
      volume_attachments = with_fifo { server.volume_attachments }
      device = volume_attachments.find { |a| a["volumeId"] == volume.id }

      if device.nil?                
        device_name = select_device_name(volume_attachments, first_device_name_letter(server))
        cloud_error("Server has too many disks attached") if device_name.nil?

        @logger.info("Attaching volume `#{volume.id}' to server `#{server.id}', device name is `#{device_name}'")
        with_fifo { volume.attach(server.id, device_name) }
        wait_resource(volume, :"in-use")        
      else
        device_name = device["device"]
        @logger.info("Volume `#{volume.id}' is already attached to server `#{server.id}' in `#{device_name}'. Skipping.")
      end

      device_name
    end

    ##
    # Select the first available device name
    #
    # @param [Array] volume_attachments Volume attachments
    # @param [String] first_device_name_letter First available letter for device names
    # @return [String] First available device name or nil is none is available
    def select_device_name(volume_attachments, first_device_name_letter)
      (first_device_name_letter.."z").each do |char|
        # Some kernels remap device names (from sd* to vd* or xvd*). 
        device_names = ["/dev/sd#{char}", "/dev/vd#{char}", "/dev/xvd#{char}"]
        # Bosh Agent will lookup for the proper device name if we set it initially to sd*.
        return "/dev/sd#{char}" if volume_attachments.select { |v| device_names.include?( v["device"]) }.empty?
        @logger.warn("`/dev/sd#{char}' is already taken")
      end

      nil
    end

    ##
    # Returns the first letter to be used on device names
    #
    # @param [Fog::Compute::Fifo::Server] server Fifo server
    # @return [String] First available letter
    def first_device_name_letter(server)
      letter = "#{FIRST_DEVICE_NAME_LETTER}"
      return letter if server.flavor.nil?
      return letter unless server.flavor.has_key?('id')
      flavor = with_fifo { @fifo.flavors.find { |f| f.id == server.flavor['id'] } }
      return letter if flavor.nil?

      letter.succ! if flavor_has_ephemeral_disk?(flavor)
      letter.succ! if flavor_has_swap_disk?(flavor)
      letter
    end

    ##
    # Detaches an Fifo volume from an Fifo server
    #
    # @param [Fog::Compute::Fifo::Server] server Fifo server
    # @param [Fog::Compute::Fifo::Volume] volume Fifo volume
    # @return [void]
    def detach_volume(server, volume)
      @logger.info("Detaching volume `#{volume.id}' from `#{server.id}'...")
      volume_attachments = with_fifo { server.volume_attachments }
      if volume_attachments.find { |a| a["volumeId"] == volume.id }
        with_fifo { volume.detach(server.id, volume.id) }
        wait_resource(volume, :available)
      else
        @logger.info("Disk `#{volume.id}' is not attached to server `#{server.id}'. Skipping.")
      end
    end

    ##
    # Compares actual server security groups with those specified at the network spec
    #
    # @param [Fog::Compute::Fifo::Server] server Fifo server
    # @param [Array] specified_sg_names Security groups specified at the network spec
    # @return [void]
    # @raise [Bosh::Clouds:NotSupported] If the security groups change, we need to recreate the VM as you can't 
    # change the security group of a running server, so we need to send the InstanceUpdater a request to do it for us
    def compare_security_groups(server, specified_sg_names)
      actual_sg_names = with_fifo { server.security_groups }.collect { |sg| sg.name }

      unless actual_sg_names.sort == specified_sg_names.sort
        raise Bosh::Clouds::NotSupported,
              "security groups change requires VM recreation: %s to %s" %
              [actual_sg_names.join(", "), specified_sg_names.join(", ")]
      end
    end

    ##
    # Compares actual server private IP addresses with the IP address specified at the network spec
    #
    # @param [Fog::Compute::Fifo::Server] server Fifo server
    # @param [String] specified_ip_address IP address specified at the network spec (if Manual network)
    # @return [void]
    # @raise [Bosh::Clouds:NotSupported] If the IP address change, we need to recreate the VM as you can't 
    # change the IP address of a running server, so we need to send the InstanceUpdater a request to do it for us
    def compare_private_ip_addresses(server, specified_ip_address)
      actual_ip_addresses = with_fifo { server.private_ip_addresses }

      unless specified_ip_address.nil? || actual_ip_addresses.include?(specified_ip_address)
        raise Bosh::Clouds::NotSupported,
              "IP address change requires VM recreation: %s to %s" %
              [actual_ip_addresses.join(", "), specified_ip_address]
      end
    end

    ##
    # Checks if the Fifo flavor has ephemeral disk
    #
    # @param [Fog::Compute::Fifo::Flavor] Fifo flavor
    # @return [Boolean] true if flavor has ephemeral disk, false otherwise
    def flavor_has_ephemeral_disk?(flavor)
      flavor.ephemeral.nil? || flavor.ephemeral.to_i <= 0 ? false : true
    end

    ##
    # Checks if the Fifo flavor has swap disk
    #
    # @param [Fog::Compute::Fifo::Flavor] Fifo flavor
    # @return [Boolean] true if flavor has swap disk, false otherwise
    def flavor_has_swap_disk?(flavor)
      flavor.swap.nil? || flavor.swap.to_i <= 0 ? false : true
    end

    ##
    # Unpacks a stemcell archive
    #
    # @param [String] tmp_dir Temporary directory
    # @param [String] image_path Local filesystem path to a stemcell image
    # @return [void]
    def unpack_image(tmp_dir, image_path)
      result = Bosh::Exec.sh("tar -C #{tmp_dir} -xzf #{image_path} 2>&1", :on_error => :return)
      if result.failed?
        @logger.error("Extracting stemcell root image failed in dir #{tmp_dir}, " +
                      "tar returned #{result.exit_status}, output: #{result.output}")
        cloud_error("Extracting stemcell root image failed. Check task debug log for details.")
      end
      root_image = File.join(tmp_dir, "root.img")
      unless File.exists?(root_image)
        cloud_error("Root image is missing from stemcell archive")
      end
    end

    ##
    # Checks if options passed to CPI are valid and can actually
    # be used to create all required data structures etc.
    #
    # @return [void]
    # @raise [ArgumentError] if options are not valid
    def validate_options
      unless @options["fifo"].is_a?(Hash) &&
          @options.has_key?("fifo") &&
          @options["fifo"]["url"] &&
          @options["fifo"]["username"] &&
          @options["fifo"]["password"]
        raise ArgumentError, "Invalid Fifo configuration parameters"
      end
      unless @options.has_key?("registry") &&
          @options["registry"].is_a?(Hash) &&
          @options["registry"]["endpoint"] &&
          @options["registry"]["user"] &&
          @options["registry"]["password"]
        raise ArgumentError, "Invalid registry configuration parameters"
      end
    end

    def initialize_registry
      registry_properties = @options.fetch('registry')
      registry_endpoint   = registry_properties.fetch('endpoint')
      registry_user       = registry_properties.fetch('user')
      registry_password   = registry_properties.fetch('password')

      @registry = Bosh::Registry::Client.new(registry_endpoint,
                                             registry_user,
                                             registry_password)
    end

  end
end
