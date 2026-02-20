variable "location" {
  description = "Región de Azure (ej: eastus)"
  type        = string
}

variable "project" {
  description = "Nombre del proyecto (para nombres/tags)"
  type        = string
}

variable "env" {
  description = "Ambiente: dev/qa/prod"
  type        = string
}

variable "owner" {
  description = "Responsable del recurso (tag Owner)"
  type        = string
}

variable "sql_admin_user" {
  description = "Usuario admin del SQL Server"
  type        = string
}

variable "sql_admin_password" {
  description = "Password admin (NO guardar en Git). Se pasa por TF_VAR_sql_admin_password"
  type        = string
  sensitive   = true
}
