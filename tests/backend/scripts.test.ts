import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { firewalldModule } from "../../src/backend/backends/firewalld";
import {
  APPLY_SH,
  iptablesModule,
  nftablesModule,
  saveScript,
  UNLOAD,
} from "../../src/backend/backends/managed";
import { ufwModule } from "../../src/backend/backends/ufw";
import {
  banScript,
  FAIL2BAN_START,
  FAIL2BAN_STATUS,
  parseFail2ban,
} from "../../src/backend/fail2ban";
import { installScript } from "../../src/backend/install";
import { parseState, READ_SCRIPT, splitSections } from "../../src/backend/read";
import { armScript, keepScript, undoScript } from "../../src/backend/rollback";
import { emptySpec } from "../../src/backend/validate";
import { FIREWALLD_SECTIONS } from "./fixtures";
import { readOutput, UFW_SECTIONS } from "./helpers";

const hasBash = spawnSync("bash", ["--version"]).status === 0;

function syntax(script: string): string {
  const result = spawnSync("bash", ["-n"], { input: script, encoding: "utf8" });
  return result.status === 0 ? "" : result.stderr;
}

describe.skipIf(!hasBash)("generated scripts", () => {
  it("are valid bash", () => {
    const ufw = parseState(readOutput({ sections: UFW_SECTIONS }), 22);
    const fwd = parseState(
      readOutput({ backend: "firewalld", sections: FIREWALLD_SECTIONS }),
      22,
    );
    const nft = parseState(readOutput({ backend: "nftables" }), 22);
    const scripts: Record<string, string> = {
      read: READ_SCRIPT,
      apply: APPLY_SH,
      unload: UNLOAD,
      fail2banStatus: FAIL2BAN_STATUS,
      fail2banStart: FAIL2BAN_START,
      ban: banScript("sshd", "203.0.113.7", true),
      install: installScript("firewalld", "apt-get"),
      keep: keepScript("0123456789abcdef"),
      undo: undoScript("0123456789abcdef"),
      saveNft: saveScript({ ...nft.managed!, enabled: true }, true),
      saveIpt: saveScript(
        { ...nft.managed!, backend: "iptables", enabled: true },
        false,
      ),
    };
    for (const [name, module] of [
      ["ufw", ufwModule],
      ["firewalld", firewalldModule],
      ["nftables", nftablesModule],
      ["iptables", iptablesModule],
    ] as const) {
      scripts[`${name}Raw`] = module.raw;
      const state = name === "ufw" ? ufw : name === "firewalld" ? fwd : nft;
      const plan = module.plan(state, {
        kind: "add",
        spec: emptySpec({ protocol: "tcp", port: "9090", comment: "x y" }),
      });
      scripts[`${name}Arm`] = armScript(
        module,
        "0123456789abcdef",
        60,
        plan.script,
      );
      scripts[`${name}Enable`] = module.plan(state, {
        kind: "enable",
        allowSsh: true,
      }).script;
    }
    scripts.ufwUpdate = ufwModule.plan(ufw, {
      kind: "update",
      id: ufw.rules[1].id,
      spec: emptySpec({ protocol: "tcp", port: "443" }),
    }).script;
    scripts.fwdUpdate = firewalldModule.plan(fwd, {
      kind: "update",
      id: fwd.rules.find((r) => r.raw === "port 8080/tcp")!.id,
      spec: emptySpec({ protocol: "tcp", port: "8081", source: "10.0.0.0/8" }),
    }).script;
    for (const [name, script] of Object.entries(scripts)) {
      expect(syntax(script), name).toBe("");
    }
  });

  it("keep and undo only touch their own folder", () => {
    expect(() => keepScript("../etc")).toThrow();
    expect(undoScript("0123456789abcdef")).toContain(
      "/var/lib/termix-firewall/pending/0123456789abcdef",
    );
  });
});

describe("script output", () => {
  it("splits sections", () => {
    expect(splitSections("@@a@@\n1\n2\n@@b-c@@\nx\n")).toEqual({
      a: "1\n2",
      "b-c": "x",
    });
  });

  it("reads the client, ports and pending folders", () => {
    const state = parseState(
      readOutput({
        detect: { sshports: "22 2222 ", client: "100.64.0.9" },
        pending: ["0123456789abcdef", "junk"],
      }),
      2200,
    );
    expect(state.ssh).toEqual({
      ports: [22, 2200, 2222],
      client: "100.64.0.9",
    });
    expect(state.pendingTokens).toEqual(["0123456789abcdef"]);
    expect(state.installed).toEqual(["ufw", "nftables", "iptables"]);
  });

  it("warns when two firewalls run", () => {
    const state = parseState(
      readOutput({ detect: { firewalld_on: "1" }, sections: UFW_SECTIONS }),
      22,
    );
    expect(state.warnings[0]).toMatch(/both running/);
  });

  it("reads fail2ban jails", () => {
    const status = parseFail2ban(
      [
        "installed=1",
        "version=Fail2Ban v1.1.0",
        "running=1",
        "@@jail sshd@@",
        "Status for the jail: sshd",
        "|- Filter",
        "|  |- Currently failed:\t2",
        "|  |- Total failed:\t40",
        "|  `- File list:\t/var/log/auth.log",
        "`- Actions",
        "   |- Currently banned:\t2",
        "   |- Total banned:\t9",
        "   `- Banned IP list:\t203.0.113.7 198.51.100.2",
      ].join("\n"),
    );
    expect(status).toMatchObject({
      installed: true,
      running: true,
      version: "Fail2Ban v1.1.0",
    });
    expect(status.jails[0]).toEqual({
      name: "sshd",
      currentlyFailed: 2,
      totalFailed: 40,
      currentlyBanned: 2,
      totalBanned: 9,
      banned: ["203.0.113.7", "198.51.100.2"],
    });
  });

  it("only installs what it knows", () => {
    expect(() => installScript("rm -rf /", "apt-get")).toThrow();
    expect(() => installScript("ufw", "brew")).toThrow();
    expect(installScript("ufw", "dnf")).toContain("dnf install -y -q ufw");
  });
});
