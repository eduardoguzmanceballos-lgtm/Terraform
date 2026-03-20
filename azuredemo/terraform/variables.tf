variable "location" {
  description = "Azure region para el despliegue"
  type        = string
  default     = "eastus"
}

variable "vm_size" {
  description = "Tamaño de la VM"
  type        = string
  default     = "Standard_B2s"
}

variable "tags" {
  description = "Tags obligatorios para gobierno"
  type        = map(string)
  default = {
    owner       = "eduardo"
    costCenter  = "demo"
    environment = "dev"
    application = "iac-governance"
  }
}