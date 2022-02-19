resource "hcloud_server" "control_planes" {
  count = var.servers_num - 1
  name  = "k3s-control-plane-${count.index + 1}"

  image              = data.hcloud_image.linux.name
  rescue             = "linux64"
  server_type        = var.control_plane_server_type
  location           = var.location
  ssh_keys           = [hcloud_ssh_key.k3s.id]
  firewall_ids       = [hcloud_firewall.k3s.id]
  placement_group_id = hcloud_placement_group.k3s.id

  labels = {
    "provisioner" = "terraform",
    "engine"      = "k3s",
  }

  connection {
    user           = "root"
    private_key    = local.ssh_private_key
    agent_identity = local.ssh_identity
    host           = self.ipv4_address
  }

  provisioner "file" {
    content     = local.ignition_config
    destination = "/root/config.ign"
  }

  # Combustion script file to install k3s-selinux
  provisioner "file" {
    content     = local.combustion_script
    destination = "/root/script"
  }

  # Install MicroOS
  provisioner "remote-exec" {
    inline = local.microOS_install_commands
  }

  # Issue a reboot command and wait for the node to reboot
  provisioner "local-exec" {
    command = "ssh ${local.ssh_args} root@${self.ipv4_address} '(sleep 2; reboot)&'; sleep 3"
  }
  provisioner "local-exec" {
    command = <<-EOT
      until ssh ${local.ssh_args} -o ConnectTimeout=2 root@${self.ipv4_address} true 2> /dev/null
      do
        echo "Waiting for MicroOS to reboot and become available..."
        sleep 3
      done
    EOT
  }

  # Generating k3s server config file
  provisioner "file" {
    content = yamlencode({
      node-name                = self.name
      server                   = "https://${local.first_control_plane_network_ip}:6443"
      token                    = random_password.k3s_token.result
      cluster-init             = true
      disable-cloud-controller = true
      disable                  = "servicelb, local-storage"
      flannel-iface            = "eth1"
      kubelet-arg              = "cloud-provider=external"
      node-ip                  = cidrhost(hcloud_network_subnet.k3s.ip_range, 258 + count.index)
      advertise-address        = cidrhost(hcloud_network_subnet.k3s.ip_range, 258 + count.index)
      tls-san                  = cidrhost(hcloud_network_subnet.k3s.ip_range, 258 + count.index)
      node-taint               = var.allow_scheduling_on_control_plane ? [] : ["node-role.kubernetes.io/master:NoSchedule"]
      node-label               = var.automatically_upgrade_k3s ? ["k3s_upgrade=true"] : []
    })
    destination = "/tmp/config.yaml"
  }

  # Install k3s server
  provisioner "remote-exec" {
    inline = local.install_k3s_server
  }

  # Upon reboot verify that the k3s server starts correctly
  provisioner "remote-exec" {
    inline = [
      "systemctl start k3s",
      <<-EOT
      timeout 120 bash <<EOF
        until systemctl status k3s > /dev/null; do
          echo "Waiting for the k3s server to start..."
          sleep 2
        done
      EOF
      EOT
    ]
  }

  network {
    network_id = hcloud_network.k3s.id
    ip         = cidrhost(hcloud_network_subnet.k3s.ip_range, 258 + count.index)
  }

  depends_on = [
    hcloud_server.first_control_plane,
    hcloud_network_subnet.k3s
  ]
}