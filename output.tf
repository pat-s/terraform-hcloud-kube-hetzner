output "cluster_name" {
  value       = var.cluster_name
  description = "Shared suffix for all resources belonging to this cluster."
}

output "network_id" {
  value       = data.hcloud_network.k3s.id
  description = "The ID of the HCloud network."
}

output "ssh_key_id" {
  value       = local.hcloud_ssh_key_id
  description = "The ID of the HCloud SSH key."
}

output "control_planes_public_ipv4" {
  value = [
    for obj in module.control_planes : obj.ipv4_address
  ]
  description = "The public IPv4 addresses of the controlplane servers."
}

output "control_planes_public_ipv6" {
  value = [
    for obj in module.control_planes : obj.ipv6_address
  ]
  description = "The public IPv6 addresses of the controlplane servers."
}

output "agents_public_ipv4" {
  value = [
    for obj in module.agents : obj.ipv4_address
  ]
  description = "The public IPv4 addresses of the agent servers."
}

output "agents_public_ipv6" {
  value = [
    for obj in module.agents : obj.ipv6_address
  ]
  description = "The public IPv6 addresses of the agent servers."
}

output "ingress_public_ipv4" {
  description = "The public IPv4 address of the Hetzner load balancer (with fallback to first control plane node)"
  value       = local.has_external_load_balancer ? local.first_control_plane_ip : hcloud_load_balancer.cluster[0].ipv4
}

output "ingress_public_ipv6" {
  description = "The public IPv6 address of the Hetzner load balancer (with fallback to first control plane node)"
  value       = local.has_external_load_balancer ? module.control_planes[keys(module.control_planes)[0]].ipv6_address : (var.load_balancer_disable_ipv6 ? null : hcloud_load_balancer.cluster[0].ipv6)
}

output "lb_control_plane_ipv4" {
  description = "The public IPv4 address of the Hetzner control plane load balancer"
  value       = one(hcloud_load_balancer.control_plane[*].ipv4)
}

output "lb_control_plane_ipv6" {
  description = "The public IPv6 address of the Hetzner control plane load balancer"
  value       = one(hcloud_load_balancer.control_plane[*].ipv6)
}


output "k3s_endpoint" {
  description = "A controller endpoint to register new nodes"
  value       = "https://${var.use_control_plane_lb ? hcloud_load_balancer_network.control_plane.*.ip[0] : module.control_planes[keys(module.control_planes)[0]].private_ipv4_address}:6443"
}

output "k3s_token" {
  description = "The k3s token to register new nodes"
  value       = local.k3s_token
  sensitive   = true
}

output "control_plane_nodes" {
  description = "The control plane nodes"
  value       = [for node in module.control_planes : node]
}

output "agent_nodes" {
  description = "The agent nodes"
  value       = [for node in module.agents : node]
}

output "domain_assignments" {
  description = "Assignments of domains to IPs based on reverse DNS"
  value = concat(
    # Propagate domain assignments from control plane and agent nodes.
    flatten([
      for node in concat(values(module.control_planes), values(module.agents)) :
      node.domain_assignments
    ]),
    # Get assignments from floating IPs.
    [for rdns in hcloud_rdns.agents : {
      domain = rdns.dns_ptr
      ips    = [rdns.ip_address]
    }]
  )
}

# Keeping for backward compatibility
output "kubeconfig_file" {
  value       = local.kubeconfig_external
  description = "Kubeconfig file content with external IP address, or internal IP address if only private ips are available"
  sensitive   = true
}

output "kubeconfig" {
  value       = local.kubeconfig_external
  description = "Kubeconfig file content with external IP address, or internal IP address if only private ips are available"
  sensitive   = true
}

output "kubeconfig_data" {
  description = "Structured kubeconfig data to supply to other providers"
  value       = local.kubeconfig_data
  sensitive   = true
}

output "cilium_values" {
  description = "Helm values.yaml used for Cilium"
  value       = local.cilium_values
  sensitive   = true
}

output "cert_manager_values" {
  description = "Helm values.yaml used for cert-manager"
  value       = local.cert_manager_values
  sensitive   = true
}

output "csi_driver_smb_values" {
  description = "Helm values.yaml used for SMB CSI driver"
  value       = local.csi_driver_smb_values
  sensitive   = true
}

output "longhorn_values" {
  description = "Helm values.yaml used for Longhorn"
  value       = local.longhorn_values
  sensitive   = true
}

output "traefik_values" {
  description = "Helm values.yaml used for Traefik"
  value       = local.traefik_values
  sensitive   = true
}

output "nginx_values" {
  description = "Helm values.yaml used for nginx-ingress"
  value       = local.nginx_values
  sensitive   = true
}

output "haproxy_values" {
  description = "Helm values.yaml used for HAProxy"
  value       = local.haproxy_values
  sensitive   = true
}

output "debug_snapshot_ids" {
  value = {
    leapmicro_arm = local.snapshot_id_by_os["leapmicro"]["arm"]
    leapmicro_x86 = local.snapshot_id_by_os["leapmicro"]["x86"]
    microos_arm   = local.snapshot_id_by_os["microos"]["arm"]
    microos_x86   = local.snapshot_id_by_os["microos"]["x86"]
  }
}

output "debug_autoscaler_config" {
  value = {
    nodepools       = var.autoscaler_nodepools
    used_os         = local.used_os
    os_requirements = local.os_requirements
  }
}

# output "debug_autoscaler_snapshot_ids" {
#   description = "Debug output showing snapshot IDs assigned to each autoscaler nodepool"
#   value = {
#     nodepools_with_snapshots = local.autoscaler_nodepools_with_snapshots
#     cluster_config           = local.cluster_config
#     imageList                = local.imageList
#     isUsingLegacyConfig      = local.isUsingLegacyConfig
#   }
# }

output "debug_autoscaler_full_config" {
  description = "Complete autoscaler configuration including the actual cluster_config that gets passed to CCM"
  value = {
    cluster_config_base64 = base64encode(jsonencode(local.cluster_config))
    cluster_config_json   = jsonencode(local.cluster_config)
    isUsingLegacyConfig   = local.isUsingLegacyConfig
    autoscaler_labels     = var.autoscaler_labels
    autoscaler_taints     = var.autoscaler_taints
  }
}

# output "debug_cluster_config_structure" {
#   description = "Detailed breakdown of the cluster_config structure being passed to CCM"
#   value = {
#     imagesForArch = local.cluster_config.imagesForArch
#     nodeConfigs = {
#       for name, config in local.cluster_config.nodeConfigs : name => {
#         snapshot_id = config.snapshot_id
#         labels      = config.labels
#         taints      = config.taints
#         # Don't include cloudInit as it's very long
#       }
#     }
#     snapshot_id_by_os = local.snapshot_id_by_os
#   }
# }
