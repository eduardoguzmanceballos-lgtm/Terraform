import json
import sys
import os

# =======================
# CONFIGURACIÓN POLICIES
# =======================
ALLOWED_REGIONS   = ["eastus", "westus2"]
BLOCKED_VM_SIZES  = ["Standard_NC6_v3", "Standard_ND6s"]
MANDATORY_TAGS    = ["owner", "costCenter", "environment", "application"]

TAGGABLE_TYPES = {
    "azurerm_resource_group",
    "azurerm_virtual_network",
    "azurerm_network_interface",
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
    "azurerm_network_security_group",
    "azurerm_public_ip",
}

# =======================
# HELPERS
# =======================
def walk_modules(module):
    if not module:
        return
    for r in module.get("resources", []):
        yield r
    for child in module.get("child_modules", []):
        yield from walk_modules(child)

def validate_mandatory_tags(resource_name, tags, findings):
    if not tags:
        findings.append({
            "type": "tags",
            "resource": resource_name,
            "message": f"Sin tags definidos (obligatorios: {MANDATORY_TAGS})"
        })
        return False
    missing = [t for t in MANDATORY_TAGS if t not in tags or not tags[t]]
    if missing:
        findings.append({
            "type": "tags",
            "resource": resource_name,
            "message": f"Tags faltantes: {missing}"
        })
        return False
    return True

# =======================
# MAIN ANALYSIS
# =======================
def analyze_plan(plan_json):
    findings = []
    risk     = "LOW"
    planned  = plan_json.get("planned_values", {}).get("root_module", {})

    for res in walk_modules(planned):
        address = res.get("address", "")
        rtype   = res.get("type", "")
        values  = res.get("values", {}) or {}

        # 1 — REGIÓN PERMITIDA
        location = (values.get("location") or "").lower()
        if location and location not in ALLOWED_REGIONS:
            findings.append({
                "type":     "region",
                "resource": address,
                "message":  f"Region '{location}' no permitida (permitidas: {ALLOWED_REGIONS})"
            })
            risk = "HIGH"

        # 2 — VM SIZE BLOQUEADA
        if rtype in ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"]:
            size = values.get("size", "")
            if size in BLOCKED_VM_SIZES:
                findings.append({
                    "type":     "vm_size",
                    "resource": address,
                    "message":  f"VM size bloqueada: {size}"
                })
                risk = "HIGH"

        # 3 — TAGS OBLIGATORIOS
        if rtype in TAGGABLE_TYPES:
            tags = values.get("tags")
            if not validate_mandatory_tags(address, tags, findings):
                risk = "HIGH"

        # 4 — PUBLIC IP EN NIC
        if rtype == "azurerm_network_interface":
            ip_configs = values.get("ip_configuration") or []
            for cfg in ip_configs:
                if cfg.get("public_ip_address_id"):
                    findings.append({
                        "type":     "network",
                        "resource": address,
                        "message":  "Public IP no permitida en NIC"
                    })
                    risk = "HIGH"

    return risk, findings

# =======================
# GITHUB STEP SUMMARY
# =======================
def write_summary(risk, findings):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    icon_risk = "✅" if risk == "LOW" else "❌"
    despega   = risk == "LOW"

    region_findings = [f for f in findings if f["type"] == "region"]
    tag_findings    = [f for f in findings if f["type"] == "tags"]
    vm_findings     = [f for f in findings if f["type"] == "vm_size"]
    net_findings    = [f for f in findings if f["type"] == "network"]

    lines = []
    lines.append("## 🛫 IaC Governance Gate — Resultado\n")
    lines.append("| Gate | Estado |")
    lines.append("|---|---|")
    lines.append(f"| 🌍 Region permitida     | {'✅ Paso' if not region_findings else '❌ Fallo'} |")
    lines.append(f"| 🏷️ Tags obligatorios    | {'✅ Paso' if not tag_findings    else '❌ Fallo'} |")
    lines.append(f"| 💻 VM size permitida    | {'✅ Paso' if not vm_findings     else '❌ Fallo'} |")
    lines.append(f"| 🔒 Red (Public IP)      | {'✅ Paso' if not net_findings    else '❌ Fallo'} |")
    lines.append(f"| 🔐 Risk level           | {icon_risk} {risk} |")
    lines.append("")

    if despega:
        lines.append("### ✅ El avion despega — governance aprobado")
        lines.append("> Todos los controles de gobierno pasaron.")
    else:
        lines.append("### ❌ El avion NO despega — governance fallo")
        lines.append("> Se detectaron violaciones de politica.")
        lines.append("")
        lines.append("#### Violaciones detectadas")
        lines.append("| Tipo | Recurso | Detalle |")
        lines.append("|---|---|---|")
        for f in findings:
            tipo = {
                "region":  "🌍 Region",
                "tags":    "🏷️ Tags",
                "vm_size": "💻 VM Size",
                "network": "🔒 Red",
            }.get(f["type"], f["type"])
            lines.append(f"| {tipo} | `{f['resource']}` | {f['message']} |")

    with open(summary_path, "a", encoding="utf-8") as s:
        s.write("\n".join(lines) + "\n")

# =======================
# ENTRYPOINT
# =======================
def main():
    with open(sys.argv[1]) as f:
        plan = json.load(f)

    risk, findings = analyze_plan(plan)

    print("\n================ RESULTADO IaC GOVERNANCE ================\n")
    print(f"🔐 Risk level: {risk}\n")
    if findings:
        print("🚨 Policy violations detected:\n")
        for f in findings:
            print(f" - ❌ {f['resource']}: {f['message']}")
        print("\n❌ Terraform Plan BLOCKED by governance policies\n")

    write_summary(risk, findings)

    if findings:
        sys.exit(2)

    print("✅ No policy violations found")
    print("✅ Terraform Plan APPROVED\n")

if __name__ == "__main__":
    main()