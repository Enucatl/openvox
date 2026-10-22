platform "ubuntu-24.04-amd64" do |plat|
  plat.inherit_from_default
  plat.use_docker_exec true
  plat.clear_provisioning
  plat.provision_with 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -qy --no-install-recommends build-essential ca-certificates curl debhelper devscripts fakeroot gettext pkg-config quilt rsync'
end
