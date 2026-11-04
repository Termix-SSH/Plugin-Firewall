import { describe, expect, it } from "vitest";
import {
  addArgs,
  firewalldModule,
  parseRichRule,
  parseZones,
  removeArgs,
} from "../../src/backend/backends/firewalld";
import { parseState } from "../../src/backend/read";
import { emptySpec } from "../../src/backend/validate";
import { FIREWALLD_SECTIONS, ZONES } from "./fixtures";
import { readOutput } from "./helpers";

describe("firewalld zones", () => {
  it("reads zones and their parts", () => {
    const zones = parseZones(ZONES);
    expect(zones.map((z) => z.zone.name)).toEqual([
      "block",
      "public",
      "trusted",
    ]);
    const pub = zones[1];
    expect(pub.zone).toMatchObject({
      isDefault: true,
      active: true,
      interfaces: ["eth0"],
      target: "default",
    });
    expect(pub.services).toEqual(["dhcpv6-client", "ssh"]);
    expect(pub.ports).toEqual(["8080/tcp", "60000-61000/udp"]);
    expect(pub.rich).toHaveLength(3);
    expect(zones[2].zone.sources).toEqual(["10.8.0.0/24"]);
  });

  it("turns zones into rules", () => {
    const state = parseState(
      readOutput({ backend: "firewalld", sections: FIREWALLD_SECTIONS }),
      22,
    );
    expect(state.backend).toBe("firewalld");
    expect(state.active).toBe(true);
    expect(state.defaultZone).toBe("public");
    expect(state.defaults).toEqual({ incoming: "reject", outgoing: "allow" });
    const ssh = state.rules.find((r) => r.service === "ssh");
    expect(ssh).toMatchObject({ port: "22", protocol: "tcp", zone: "public" });
    expect(state.rules.filter((r) => r.zone === "public")).toHaveLength(7);
  });

  it("reads simple rich rules and keeps others delete only", () => {
    const drop = parseRichRule(
      "public",
      'rule family="ipv4" source address="203.0.113.0/24" drop',
    );
    expect(drop).toMatchObject({
      action: "deny",
      source: "203.0.113.0/24",
      family: "ipv4",
    });
    expect(drop.deleteOnly).toBeFalsy();
    const pg = parseRichRule(
      "public",
      'rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept',
    );
    expect(pg).toMatchObject({
      action: "allow",
      port: "5432",
      protocol: "tcp",
    });
    const logged = parseRichRule(
      "public",
      'rule family="ipv4" source address="10.0.0.0/8" log prefix="x" accept',
    );
    expect(logged.deleteOnly).toBe(true);
  });
});

describe("firewalld commands", () => {
  it("uses plain ports when it can, rich rules when it must", () => {
    expect(addArgs(emptySpec({ protocol: "tcp", port: "80,443" }))).toEqual([
      "--add-port=80/tcp",
      "--add-port=443/tcp",
    ]);
    expect(addArgs(emptySpec({ protocol: "any", port: "53" }))).toEqual([
      "--add-port=53/tcp",
      "--add-port=53/udp",
    ]);
    expect(addArgs(emptySpec({ service: "http" }))).toEqual([
      "--add-service=http",
    ]);
    expect(
      addArgs(
        emptySpec({
          action: "deny",
          protocol: "tcp",
          port: "22",
          source: "198.51.100.7",
        }),
      ),
    ).toEqual([
      '--add-rich-rule=rule family="ipv4" source address="198.51.100.7" port port="22" protocol="tcp" drop',
    ]);
    expect(() => addArgs(emptySpec({ direction: "out" }))).toThrow(/incoming/);
    expect(() => addArgs(emptySpec({ iface: "eth0" }))).toThrow(/zone/);
  });

  it("removes by what the rule is", () => {
    const state = parseState(
      readOutput({ backend: "firewalld", sections: FIREWALLD_SECTIONS }),
      22,
    );
    const port = state.rules.find((r) => r.raw === "port 8080/tcp")!;
    expect(removeArgs(port)).toBe("--remove-port=8080/tcp");
    const rich = state.rules.find(
      (r) => r.raw.startsWith("rule") && r.action === "deny",
    )!;
    expect(removeArgs(rich)).toBe(`--remove-rich-rule=${rich.raw}`);
  });

  it("plans zone and rule changes on runtime and permanent", () => {
    const state = parseState(
      readOutput({ backend: "firewalld", sections: FIREWALLD_SECTIONS }),
      22,
    );
    const add = firewalldModule.plan(state, {
      kind: "add",
      spec: emptySpec({ protocol: "tcp", port: "9000" }),
    });
    expect(add.script).toContain('fw() { firewall-cmd "$@"');
    expect(add.script).toContain("fw --zone='public' '--add-port=9000/tcp'");
    const target = firewalldModule.plan(state, {
      kind: "zoneTarget",
      zone: "public",
      target: "DROP",
    });
    expect(target.script).toContain("--set-target='DROP'");
    expect(target.after.defaults?.incoming).toBe("deny");
    expect(() =>
      firewalldModule.plan(state, {
        kind: "zoneTarget",
        zone: "nope",
        target: "DROP",
      }),
    ).toThrow(/no zone/);
    expect(() =>
      firewalldModule.plan(state, {
        kind: "defaults",
        defaults: { outgoing: "deny" },
      }),
    ).toThrow(/outgoing/);
  });

  it("needs firewalld running for rule changes", () => {
    const state = parseState(
      readOutput({
        backend: "firewalld",
        detect: { firewalld_on: "0" },
        sections: FIREWALLD_SECTIONS,
      }),
      22,
    );
    expect(state.active).toBe(false);
    expect(() =>
      firewalldModule.plan(state, {
        kind: "add",
        spec: emptySpec({ port: "80", protocol: "tcp" }),
      }),
    ).toThrow(/on first/);
    expect(
      firewalldModule.plan(state, { kind: "enable", allowSsh: true }).script,
    ).toContain("--add-port=22/tcp");
  });
});
