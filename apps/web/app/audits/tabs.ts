export type TabKey = "console" | "triage" | "findings" | "attack-surface" | "report" | "chat";

export function tabs(id: string, active: TabKey) {
  return [
    { href: `/audits/${id}`,                  label: "console",       active: active === "console" },
    { href: `/audits/${id}/triage`,           label: "triage",        active: active === "triage" },
    { href: `/audits/${id}/findings`,         label: "findings",      active: active === "findings" },
    { href: `/audits/${id}/attack-surface`,   label: "surface",       active: active === "attack-surface" },
    { href: `/audits/${id}/report`,           label: "report",        active: active === "report" },
    { href: `/audits/${id}/chat`,             label: "ask_auditor",   active: active === "chat" },
  ];
}
