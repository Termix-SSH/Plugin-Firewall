import { describe, expect, it } from "vitest";
import {
  emptyDoc,
  iptablesModule,
  iptRules,
  nftablesModule,
  nftRule,
  readDoc,
  renderIptables,
  renderNft,
  saveScript,
} from "../../src/backend/backends/managed";
import type { ManagedDoc } from "../../src/backend/backends/types";
import { parseState } from "../../src/backend/read";
import { emptySpec } from "../../src/backend/validate";
import { readOutput } from "./helpers";

const doc: ManagedDoc = {
  version: 1,
  backend: "nftables",
  enabled: true,
  defaults: { incoming: "deny", outgoing: "allow" },
  rules: [
    { ...emptySpec({ protocol: "tcp", port: "22" }), id: "aaaaaaaa" },
    {
      ...emptySpec({ protocol: "tcp", port: "80,443", comment: "web" }),
      id: "bbbbbbbb",
    },
    {
      ...emptySpec({ action: "deny", source: "2001:db8::/32" }),
      family: "ipv6",
      id: "cccccccc",
    },
    {
      ...emptySpec({
        protocol: "any",
        port: "53",
        direction: "out",
        iface: "eth0",
      }),
      id: "dddddddd",
    },
  ],
};

describe("nftables rules", () => {
  it("renders each rule", () => {
    expect(nftRule(doc.rules[0])).toBe(
      'tcp dport 22 accept comment "tx:aaaaaaaa"',
    );
    expect(nftRule(doc.rules[1])).toBe(
      'tcp dport { 80, 443 } accept comment "tx:bbbbbbbb web"',
    );
    expect(nftRule(doc.rules[2])).toBe(
      'ip6 saddr 2001:db8::/32 drop comment "tx:cccccccc"',
    );
    expect(nftRule(doc.rules[3])).toBe(
      'oifname "eth0" meta l4proto { tcp, udp } th dport 53 accept comment "tx:dddddddd"',
    );
  });

  it("renders the table with the default at the end", () => {
    const text = renderNft(doc);
    expect(text).toContain("delete table inet termix");
    expect(text).toContain(
      "type filter hook input priority -5; policy accept;",
    );
    expect(text.indexOf("tcp dport 22 accept")).toBeLessThan(
      text.indexOf("\t\tdrop\n"),
    );
    expect(text).not.toContain("\t\treject");
  });
});

describe("iptables rules", () => {
  it("splits families and protocols", () => {
    expect(iptRules(doc.rules[1], "4")).toEqual([
      '-A TERMIX-IN -p tcp -m multiport --dports 80,443 -m comment --comment "tx:bbbbbbbb web" -j ACCEPT',
    ]);
    expect(iptRules(doc.rules[2], "4")).toEqual([]);
    expect(iptRules(doc.rules[2], "6")).toHaveLength(1);
    expect(iptRules(doc.rules[3], "4")).toHaveLength(2);
    expect(
      iptRules(
        {
          ...emptySpec({ protocol: "tcp", port: "8000-8100" }),
          id: "eeeeeeee",
        },
        "4",
      )[0],
    ).toContain("--dports 8000:8100");
  });

  it("renders a restore file", () => {
    const v6 = renderIptables({ ...doc, backend: "iptables" }, "6");
    expect(v6).toContain("*filter");
    expect(v6).toContain("-A TERMIX-IN -p ipv6-icmp -j ACCEPT");
    expect(v6).toContain("-A TERMIX-IN -j DROP");
    expect(v6.trim().endsWith("COMMIT")).toBe(true);
  });
});

describe("rules file", () => {
  it("reads good rules and skips bad ones", () => {
    const { doc: read, dropped } = readDoc(
      JSON.stringify({
        enabled: true,
        defaults: { incoming: "reject", outgoing: "nope" },
        rules: [
          doc.rules[0],
          { id: "zz", port: "22" },
          { ...doc.rules[1], port: "99999" },
        ],
      }),
      "nftables",
    );
    expect(read.enabled).toBe(true);
    expect(read.defaults).toEqual({ incoming: "reject", outgoing: "allow" });
    expect(read.rules).toHaveLength(1);
    expect(dropped).toBe(2);
  });

  it("starts empty with incoming denied", () => {
    expect(readDoc("", "iptables").doc).toEqual(emptyDoc("iptables"));
  });

  it("checks rules before it saves them", () => {
    const nft = saveScript(doc, true);
    expect(nft).toContain('nft -c -f "$T/termix.nft"');
    expect(nft).toContain("systemctl enable termix-firewall");
    const ipt = saveScript({ ...doc, backend: "iptables" }, false);
    expect(ipt).toContain("iptables-restore --test --noflush");
    expect(ipt).not.toContain("systemctl");
  });
});

describe("managed plans", () => {
  const nftState = () =>
    parseState(
      readOutput({
        backend: "nftables",
        detect: { termix: "nftables" },
        sections: {
          "tx-state": "BACKEND=nftables\nENABLED=1",
          "tx-rules": JSON.stringify(doc),
          "tx-service": "enabled",
          "tx-live": "loaded",
          "tx-version": "nftables v1.1.3",
          "tx-other": "4",
          "tx-docker": "",
        },
      }),
      22,
    );

  it("reads the state with other tools' rules counted", () => {
    const state = nftState();
    expect(state.active).toBe(true);
    expect(state.persistent).toBe(true);
    expect(state.otherRules).toBe(4);
    expect(state.rules).toHaveLength(4);
    expect(state.warnings.some((w) => w.includes("Other tools"))).toBe(true);
  });

  it("adds, removes and refuses limit", () => {
    const state = nftState();
    const add = nftablesModule.plan(state, {
      kind: "add",
      spec: emptySpec({ protocol: "tcp", port: "8443" }),
    });
    expect(add.after.rules).toHaveLength(5);
    expect(add.script).toContain("base64 -d");
    const remove = nftablesModule.plan(state, {
      kind: "remove",
      id: "bbbbbbbb",
    });
    expect(remove.after.rules.map((r) => r.id)).not.toContain("bbbbbbbb");
    expect(() =>
      nftablesModule.plan(state, {
        kind: "add",
        spec: emptySpec({ action: "limit", port: "22", protocol: "tcp" }),
      }),
    ).toThrow(/UFW/);
  });

  it("puts SSH first when it turns on", () => {
    const state = parseState(readOutput({ backend: "iptables" }), 2222);
    expect(state.active).toBe(false);
    const plan = iptablesModule.plan(state, { kind: "enable", allowSsh: true });
    expect(plan.after.active).toBe(true);
    expect(plan.after.rules.map((r) => r.port)).toEqual(["22", "2222"]);
  });
});
