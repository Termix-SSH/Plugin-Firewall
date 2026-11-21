import { describe, expect, it } from "vitest";
import {
  POWERSHELL,
  encodedCommand,
  parseWindowsState,
  planWindows,
  psq,
  ruleCommand,
  windowsArmScript,
  windowsKeepScript,
} from "../../src/backend/backends/windows.js";
import { looksLikeWindows } from "../../src/backend/remote.js";
import { lockoutReason } from "../../src/backend/guard.js";
import { snapshotOf } from "../../src/backend/backends/types.js";

const READ = JSON.stringify({
  profiles: [
    { name: "Domain", enabled: "True", inbound: "Block", outbound: "Allow" },
    { name: "Public", enabled: "True", inbound: "Block", outbound: "Allow" },
  ],
  rules: [
    {
      name: "OpenSSH-Server-In-TCP",
      display: "OpenSSH SSH Server (sshd)",
      group: "",
      enabled: "True",
      direction: "Inbound",
      action: "Allow",
      protocol: "TCP",
      port: "22",
      remote: "Any",
    },
    {
      name: "termix-aaaaaaaaaaaa",
      display: "Web",
      group: "Termix",
      enabled: "True",
      direction: "Inbound",
      action: "Allow",
      protocol: "TCP",
      port: "80,443",
      remote: "10.0.0.0/8",
    },
    {
      name: "old",
      display: "Off",
      group: "",
      enabled: "False",
      direction: "Inbound",
      action: "Block",
      protocol: "Any",
      port: "Any",
      remote: "Any",
    },
  ],
  total: 400,
  sshPort: 22,
  tasks: "termix-fw-abcdef012345",
  os: "Microsoft Windows Server 2022",
  admin: true,
  client: "100.64.0.5",
});

const spec = {
  action: "allow" as const,
  direction: "in" as const,
  protocol: "tcp" as const,
  port: "3389",
  source: "",
  destination: "",
  iface: "",
  family: "any" as const,
  comment: "RDP",
};

describe("Windows Firewall", () => {
  it("knows a Windows host from ver", () => {
    expect(looksLikeWindows("Microsoft Windows [Version 10.0.20348]")).toBe(
      true,
    );
    expect(
      looksLikeWindows("'ver' is not recognized as the name of a cmdlet"),
    ).toBe(true);
    expect(looksLikeWindows("bash: ver: command not found")).toBe(false);
  });

  it("reads profiles, enabled rules and waiting undo tasks", () => {
    const state = parseWindowsState(`noise\n${READ}`, 22);
    expect(state.backend).toBe("windows");
    expect(state.active).toBe(true);
    expect(state.defaults).toEqual({ incoming: "deny", outgoing: "allow" });
    expect(state.rules.map((r) => r.id)).toEqual([
      "OpenSSH-Server-In-TCP",
      "termix-aaaaaaaaaaaa",
    ]);
    expect(state.rules[0]).toMatchObject({ managed: false, deleteOnly: true });
    expect(state.rules[1]).toMatchObject({
      managed: true,
      port: "80,443",
      source: "10.0.0.0/8",
    });
    expect(state.pendingTokens).toEqual(["abcdef012345"]);
    expect(state.otherRules).toBe(397);
  });

  it("writes rules in the Termix group and refuses what Windows can't do", () => {
    expect(ruleCommand(spec, "termix-1")).toBe(
      "New-NetFirewallRule -Name 'termix-1' -DisplayName 'RDP' -Group 'Termix' -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort '3389' | Out-Null",
    );
    expect(() => ruleCommand({ ...spec, action: "limit" }, "x")).toThrow();
    expect(() => ruleCommand({ ...spec, protocol: "any" }, "x")).toThrow();
    expect(() => ruleCommand({ ...spec, port: "22; calc" }, "x")).toThrow();
    expect(() => ruleCommand({ ...spec, source: "1.2.3.4'" }, "x")).toThrow();
    expect(psq("it's")).toBe("'it''s'");
  });

  it("warns before a block rule cuts off SSH", () => {
    const state = parseWindowsState(READ, 22);
    const plan = planWindows(state, {
      kind: "add",
      spec: { ...spec, action: "deny", port: "22", comment: "" },
    });
    expect(plan.script).toContain("-Action Block");
    expect(lockoutReason(state, plan.after, snapshotOf(state))).toMatch(
      /port 22/,
    );
  });

  it("sets defaults and removes rules by name", () => {
    const state = parseWindowsState(READ, 22);
    expect(
      planWindows(state, { kind: "defaults", defaults: { incoming: "allow" } })
        .script,
    ).toBe(
      "Set-NetFirewallProfile -All -DefaultInboundAction Allow -DefaultOutboundAction Allow",
    );
    expect(
      planWindows(state, { kind: "remove", id: "termix-aaaaaaaaaaaa" }).script,
    ).toBe("Remove-NetFirewallRule -Name 'termix-aaaaaaaaaaaa'");
    expect(() =>
      planWindows(state, { kind: "defaultZone", zone: "public" }),
    ).toThrow();
  });

  it("arms an undo task and encodes scripts for PowerShell", () => {
    const script = windowsArmScript("abcdef012345", 60, "Set-X");
    expect(script.startsWith(POWERSHELL)).toBe(true);
    expect(script).toContain("netsh advfirewall export");
    expect(script).toContain("termix-fw-abcdef012345");
    expect(script).toContain("AddSeconds(60)");
    expect(windowsKeepScript("abcdef012345")).toContain(
      "Unregister-ScheduledTask",
    );
    expect(() => windowsKeepScript("bad token")).toThrow();
    const command = encodedCommand(`${POWERSHELL}Write-Output 'hi'`);
    const encoded = command.split(" ").at(-1)!;
    expect(Buffer.from(encoded, "base64").toString("utf16le")).toBe(
      "Write-Output 'hi'",
    );
  });
});
