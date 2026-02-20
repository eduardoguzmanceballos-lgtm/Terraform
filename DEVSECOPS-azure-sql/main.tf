resource "random_string" "suffix" {
  length  = 6
  lower   = true
  upper   = false
  numeric = true
  special = false
}

locals {
  tags = {
    Project = var.project
    Env     = var.env
    Owner   = var.owner
  }

  rg_name     = "${var.project}-${var.env}-rg"
  sqlsrv_name = "${var.project}-${var.env}-sql-${random_string.suffix.result}"
  db_name     = "${var.project}-${var.env}-db"
}
resource "azurerm_resource_group" "rg" {
  name     = local.rg_name
  location = var.location
  tags     = local.tags
}
resource "azurerm_mssql_server" "sql" {
  name                         = local.sqlsrv_name
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"

  administrator_login          = var.sql_admin_user
  administrator_login_password = var.sql_admin_password

  tags = local.tags
}
resource "azurerm_mssql_database" "db" {
  name      = local.db_name
  server_id = azurerm_mssql_server.sql.id

  # Lo más barato en DTU suele ser Basic
  sku_name  = "Basic"

  tags = local.tags
}
