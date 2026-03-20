output "demo_region" {
  description = "Región donde se desplegó la infraestructura"
  value       = azurerm_resource_group.rg.location
}

output "demo_vm_size" {
  description = "Tamaño de la VM desplegada"
  value       = azurerm_linux_virtual_machine.vm.size
}

output "demo_public_ip_id" {
  description = "ID de la IP pública — riesgo de seguridad para el demo"
  value       = azurerm_public_ip.pip.id
}