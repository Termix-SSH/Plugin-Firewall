import { describe, expect, it } from "vitest";
import {
  parseTuple,
  parseUfwRules,
  ufwArgs,
  ufwModule,
} from "../../src/backend/backends/ufw";
import { parseState } from "../../src/backend/read";
import { emptySpec } from "../../src/backend/validate";
import { readOutput, UFW_SECTIONS } from "./helpers";

describe("ufw tuples", () => {
  it("reads a plain rule with a comment", () => {
    const t = parseTuple(
      "### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in comment=776562",
    );
    expect(t).toMatchObject({
      action: "allow",
      protocol: "tcp",
      port: "80,443",
      source: "",
      comment: "web",
    });
  });

  it("reads log, interface, range and source", () => {
    const t = parseTuple(
      "### tuple ### deny_log udp 6000:6010 0.0.0.0/0 any 203.0.113.0/24 in_eth0",
    );
    expect(t).toMatchObject({
      action: "deny",
      log: "log",
      port: "6000-6010",
      source: "203.0.113.0/24",
      iface: "eth0",
    });
  });

  it("reads app profile rules", () => {
    const t = parseTuple(
      "### tuple ### allow tcp 22 OpenSSH 0.0.0.0/0 any - 0.0.0.0/0 in",
    );
    expect(t).toMatchObject({
      app: "OpenSSH",
      port: "22",
      direction: "in",
      sourceApp: "",
    });
  });

  it("refuses lines it can't read", () => {
    expect(parseTuple("### tuple ### allow tcp")).toBeNull();
    expect(
      parseTuple("### tuple ### explode tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"),
    ).toBeNull();
  });

  it("merges v4 and v6 copies into one rule", () => {
    const rules = parseUfwRules(
      UFW_SECTIONS["ufw-rules"],
      UFW_SECTIONS["ufw-rules6"],
    );
    expect(rules).toHaveLength(2);
    expect(rules.map((r) => r.family)).toEqual(["any", "any"]);
    expect(rules.map((r) => r.position)).toEqual([1, 2]);
  });

  it("keeps a v6 only rule after the v4 ones", () => {
    const rules = parseUfwRules(
      "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
      "### tuple ### allow tcp 22 ::/0 any ::/0 in\n### tuple ### allow udp 53 ::/0 any 2001:db8::/32 in",
    );
    expect(rules).toHaveLength(2);
    expect(rules[1]).toMatchObject({
      family: "ipv6",
      source: "2001:db8::/32",
      position: 3,
    });
  });

  it("marks routed and odd rules read only", () => {
    const rules = parseUfwRules(
      "### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1\n### tuple ### allow tcp 22 0.0.0.0/0 2000 0.0.0.0/0 in",
      "",
    );
    expect(rules.every((r) => !r.managed && r.readOnlyReason)).toBe(true);
  });
});

describe("ufw commands", () => {
  it("builds add and delete words", () => {
    const spec = emptySpec({
      protocol: "tcp",
      port: "8000-8100",
      source: "10.0.0.0/8",
      comment: "app range",
    });
    expect(ufwArgs(spec)).toEqual([
      "allow",
      "in",
      "proto",
      "tcp",
      "from",
      "10.0.0.0/8",
      "to",
      "any",
      "port",
      "8000:8100",
      "comment",
      "app range",
    ]);
    expect(ufwArgs(spec, { delete: true })).not.toContain("comment");
  });

  it("limits a family with no address", () => {
    expect(
      ufwArgs(emptySpec({ family: "ipv6", port: "22", protocol: "tcp" })),
    ).toContain("::/0");
  });

  it("plans add, update and remove", () => {
    const state = parseState(readOutput({ sections: UFW_SECTIONS }), 22);
    const add = ufwModule.plan(state, {
      kind: "add",
      spec: emptySpec({ protocol: "tcp", port: "8080" }),
    });
    expect(add.script).toContain(
      "ufw allow in proto tcp from any to any port 8080",
    );
    expect(add.after.rules).toHaveLength(3);

    expect(() =>
      ufwModule.plan(state, {
        kind: "add",
        spec: emptySpec({ protocol: "tcp", port: "22" }),
      }),
    ).toThrow(/already/);

    const web = state.rules[1];
    const update = ufwModule.plan(state, {
      kind: "update",
      id: web.id,
      spec: emptySpec({ protocol: "tcp", port: "443" }),
    });
    expect(update.script).toContain(
      "ufw --force delete allow in proto tcp from any to any port 80,443",
    );
    expect(update.script).toContain(
      "ufw insert 2 allow in proto tcp from any to any port 443",
    );

    const remove = ufwModule.plan(state, {
      kind: "remove",
      id: state.rules[0].id,
    });
    expect(remove.after.rules).toHaveLength(1);
  });

  it("allows SSH before turning on", () => {
    const state = parseState(
      readOutput({
        sections: {
          ...UFW_SECTIONS,
          "ufw-status": "Status: inactive",
          "ufw-rules": "",
          "ufw-rules6": "",
        },
      }),
      2222,
    );
    const plan = ufwModule.plan(state, { kind: "enable", allowSsh: true });
    expect(plan.script).toContain("port 22 comment 'Termix SSH'");
    expect(plan.script).toContain("port 2222 comment 'Termix SSH'");
    expect(plan.script).toContain("ufw --force enable");
    expect(plan.after.active).toBe(true);
  });

  it("refuses firewalld only things", () => {
    const state = parseState(readOutput({ sections: UFW_SECTIONS }), 22);
    expect(() =>
      ufwModule.plan(state, {
        kind: "add",
        spec: emptySpec({ service: "http" }),
      }),
    ).toThrow(/firewalld/);
    expect(() =>
      ufwModule.plan(state, { kind: "defaultZone", zone: "public" }),
    ).toThrow(/firewalld/);
  });
});
