import { describe, expect, it } from "vitest";
import { snapshotOf } from "../../src/backend/backends/types";
import { ufwModule } from "../../src/backend/backends/ufw";
import { isRisky, lockoutReason, sshReach } from "../../src/backend/guard";
import { parseState } from "../../src/backend/read";
import { emptySpec } from "../../src/backend/validate";
import type { Rule } from "../../src/shared/types";
import { readOutput, UFW_SECTIONS } from "./helpers";
import { FIREWALLD_SECTIONS } from "./fixtures";

const rule = (over: Partial<Rule>): Rule => ({
  ...emptySpec(over),
  id: "x",
  managed: true,
  raw: "",
  ...over,
});

describe("ssh reach", () => {
  const snap = (rules: Rule[], incoming: "allow" | "deny" = "deny") => ({
    active: true,
    defaults: { incoming, outgoing: "allow" as const },
    rules,
    zones: [],
    defaultZone: "",
  });

  it("follows the first matching rule", () => {
    expect(
      sshReach(
        "ufw",
        snap([rule({ protocol: "tcp", port: "22" })]),
        22,
        "10.0.0.5",
      ).allowed,
    ).toBe(true);
    expect(
      sshReach(
        "ufw",
        snap([rule({ action: "deny", port: "22" }), rule({ port: "22" })]),
        22,
        "10.0.0.5",
      ).allowed,
    ).toBe(false);
    expect(sshReach("ufw", snap([]), 22, "10.0.0.5").allowed).toBe(false);
    expect(sshReach("ufw", snap([], "allow"), 22, "10.0.0.5").allowed).toBe(
      true,
    );
    expect(
      sshReach("ufw", { ...snap([]), active: false }, 22, "10.0.0.5").allowed,
    ).toBe(true);
  });

  it("checks the source range against the client", () => {
    const fromLan = rule({ protocol: "tcp", port: "22", source: "10.0.0.0/8" });
    expect(sshReach("ufw", snap([fromLan]), 22, "10.0.0.5").allowed).toBe(true);
    expect(sshReach("ufw", snap([fromLan]), 22, "192.168.1.5").allowed).toBe(
      false,
    );
    // An unknown client never counts as allowed by a source rule.
    expect(sshReach("ufw", snap([fromLan]), 22, "").allowed).toBe(false);
    const blockOther = rule({ action: "deny", source: "203.0.113.0/24" });
    expect(
      sshReach("ufw", snap([blockOther], "allow"), 22, "10.0.0.5").allowed,
    ).toBe(true);
  });

  it("errs on the safe side for interfaces", () => {
    const denyOnEth = rule({ action: "deny", port: "22", iface: "eth0" });
    expect(
      sshReach("ufw", snap([denyOnEth], "allow"), 22, "10.0.0.5").allowed,
    ).toBe(false);
    const allowOnEth = rule({ port: "22", iface: "eth0" });
    expect(sshReach("ufw", snap([allowOnEth]), 22, "10.0.0.5").allowed).toBe(
      false,
    );
  });

  it("uses the zone for firewalld", () => {
    const state = parseState(
      readOutput({ backend: "firewalld", sections: FIREWALLD_SECTIONS }),
      22,
    );
    expect(
      sshReach("firewalld", snapshotOf(state), 22, "10.0.0.5").allowed,
    ).toBe(true);
    // The drop rich rule for 203.0.113.0/24 wins over the ssh service.
    expect(
      sshReach("firewalld", snapshotOf(state), 22, "203.0.113.9").allowed,
    ).toBe(false);
    // Sources in the trusted zone get its ACCEPT target.
    const noSsh = {
      ...snapshotOf(state),
      rules: state.rules.filter((r) => r.service !== "ssh"),
    };
    expect(sshReach("firewalld", noSsh, 22, "10.8.0.7").allowed).toBe(true);
    expect(sshReach("firewalld", noSsh, 22, "10.0.0.5").allowed).toBe(false);
  });
});

describe("lockout check", () => {
  const state = parseState(readOutput({ sections: UFW_SECTIONS }), 22);

  it("stops a rule that blocks SSH", () => {
    const plan = ufwModule.plan(state, {
      kind: "add",
      spec: emptySpec({ action: "deny", protocol: "tcp", port: "22" }),
    });
    // UFW appends, so the allow above still wins.
    expect(lockoutReason(state, plan.after, snapshotOf(state))).toBe("");
    const ssh = state.rules[0];
    const removal = ufwModule.plan(state, { kind: "remove", id: ssh.id });
    expect(lockoutReason(state, removal.after, snapshotOf(state))).toMatch(
      /no rule allows port 22/,
    );
  });

  it("knows which changes are risky", () => {
    expect(isRisky(state, { kind: "enable", allowSsh: true })).toBe(true);
    expect(isRisky(state, { kind: "disable" })).toBe(false);
    expect(
      isRisky(state, { kind: "defaults", defaults: { incoming: "allow" } }),
    ).toBe(false);
    expect(
      isRisky(state, { kind: "defaults", defaults: { incoming: "deny" } }),
    ).toBe(true);
    expect(
      isRisky(state, {
        kind: "add",
        spec: emptySpec({ protocol: "tcp", port: "8080" }),
      }),
    ).toBe(false);
    expect(
      isRisky(state, { kind: "add", spec: emptySpec({ action: "deny" }) }),
    ).toBe(true);
    expect(isRisky(state, { kind: "remove", id: state.rules[0].id })).toBe(
      true,
    );
    expect(isRisky(state, { kind: "remove", id: state.rules[1].id })).toBe(
      false,
    );
  });
});
