import { afterEach, describe, expect, it } from "vitest";
import {
  readOutput,
  startServer,
  UFW_SECTIONS,
  type TestServer,
} from "./helpers";

let server: TestServer | null = null;

afterEach(async () => {
  await server?.close();
  server = null;
});

const ARMED = { match: "termix_change()", stdout: "@@armed@@\n@@applied@@\n" };
const PROBE = { match: "echo termix-ok", stdout: "termix-ok\n" };
const KEEP = { match: 'echo "state=kept"', stdout: "state=kept\n" };
const UNDO = { match: 'echo "state=reverted"', stdout: "state=reverted\n" };

function readReply(pending: string[] = []) {
  return {
    match: "sec detect",
    stdout: readOutput({ sections: UFW_SECTIONS, pending }),
  };
}

async function start(options: Parameters<typeof startServer>[0] = {}) {
  server = await startServer(options);
  server.ssh.replies.push(ARMED, PROBE, KEEP, UNDO, readReply());
  return server;
}

/** Makes the next reads report a rollback folder on the host. */
function hostHasPending(s: TestServer, token: string) {
  const index = s.ssh.replies.findIndex((r) => r.match === "sec detect");
  s.ssh.replies[index] = readReply([token]);
}

const SSH_RULE_ID = async (s: TestServer) =>
  (await s.request("GET", "/1/status")).body.rules[0].id as string;

describe("firewall routes", () => {
  it("reports the firewall on a host", async () => {
    const s = await start();
    const res = await s.request("GET", "/1/status");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      backend: "ufw",
      active: true,
      canEdit: true,
      pending: null,
      ssh: { ports: [22], client: "10.0.0.5" },
    });
    expect(res.body.rules).toHaveLength(2);
    expect(res.body.managed).toBeUndefined();
    expect(s.ssh.calls[0].command).toContain("sudo -n");
  });

  it("needs the use permission", async () => {
    const s = await start({ permissions: [] });
    expect((await s.request("GET", "/1/status")).status).toBe(403);
  });

  it("hides hosts the user can't reach", async () => {
    const s = await start({ level: "none" });
    expect((await s.request("GET", "/1/status")).status).toBe(404);
  });

  it("refuses a host with Firewall turned off", async () => {
    const s = await start({ hostSettings: { enableFirewall: false } });
    const res = await s.request("GET", "/1/status");
    expect(res.status).toBe(403);
    expect(res.body.code).toBe("disabled");
    expect(s.ssh.calls).toHaveLength(0);
  });

  it("needs edit access for changes", async () => {
    const s = await start({ level: "connect" });
    expect((await s.request("GET", "/1/status")).body.canEdit).toBe(false);
    const res = await s.request("POST", "/1/rules", {
      protocol: "tcp",
      port: "8080",
    });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe("HOST_EDIT_REQUIRED");
  });

  it("blocks every change on a read only host", async () => {
    const s = await start({ hostSettings: { readOnly: true } });
    for (const [method, path, body] of [
      ["POST", "/1/rules", { protocol: "tcp", port: "8080" }],
      ["DELETE", "/1/rules/abc"],
      ["POST", "/1/defaults", { incoming: "deny" }],
      ["POST", "/1/enable", {}],
      ["POST", "/1/disable", {}],
      ["POST", "/1/install", { what: "ufw" }],
      ["POST", "/1/fail2ban/ban", { jail: "sshd", ip: "203.0.113.7" }],
    ] as const) {
      const res = await s.request(method, path, body);
      expect(res.status, path).toBe(403);
      expect(res.body.code).toBe("readOnly");
    }
  });

  it("adds a rule that does not touch SSH right away", async () => {
    const s = await start();
    const res = await s.request("POST", "/1/rules", {
      protocol: "tcp",
      port: "8080",
      comment: "app",
    });
    expect(res.status).toBe(200);
    expect(res.body.pending).toBeNull();
    const call = s.ssh.calls.find((c) => c.stdin.includes("port 8080"));
    expect(call?.stdin).toContain(
      "ufw allow in proto tcp from any to any port 8080 comment app",
    );
    expect(call?.stdin).not.toContain("termix_change");
    expect(s.mock.audits.at(-1)).toMatchObject({
      action: "firewall.rule_add",
      success: true,
    });
  });

  it("refuses bad rules before reaching the host", async () => {
    const s = await start();
    const res = await s.request("POST", "/1/rules", {
      protocol: "tcp",
      port: "22; reboot",
    });
    expect(res.status).toBe(400);
    expect(s.ssh.calls).toHaveLength(0);
  });

  it("stops a change that cuts off SSH, then runs it with a timer when forced", async () => {
    const s = await start();
    const id = await SSH_RULE_ID(s);
    const blocked = await s.request("DELETE", `/1/rules/${id}`);
    expect(blocked.status).toBe(409);
    expect(blocked.body.code).toBe("SSH_LOCKOUT");
    expect(
      s.ssh.calls.some((c) => c.stdin.includes("ufw --force delete")),
    ).toBe(false);

    const forced = await s.request("DELETE", `/1/rules/${id}?force=1`);
    expect(forced.status).toBe(200);
    expect(forced.body.pending).toMatchObject({ reachable: true, hostId: 1 });
    const arm = s.ssh.calls.find((c) => c.stdin.includes("termix_change"));
    expect(arm?.stdin).toContain(
      "systemd-run --quiet --unit=termix-fw-revert-",
    );
    expect(arm?.stdin).toContain("--on-active=60s");

    const token = forced.body.pending.token as string;
    hostHasPending(s, token);
    const status = await s.request("GET", "/1/status");
    expect(status.body.pending.token).toBe(token);

    const again = await s.request("POST", "/1/rules", {
      protocol: "tcp",
      port: "9000",
    });
    expect(again.status).toBe(409);
    expect(again.body.code).toBe("pending");

    const keep = await s.request("POST", "/1/pending/keep");
    expect(keep.status).toBe(200);
    expect(keep.body.state).toBe("kept");
    expect((await s.request("GET", "/1/pending")).body.pending).toBeNull();
  });

  it("undoes a pending change", async () => {
    const s = await start({ hostSettings: { rollbackSeconds: 30 } });
    const res = await s.request("POST", "/1/defaults", { incoming: "reject" });
    expect(res.status).toBe(200);
    expect(res.body.pending).not.toBeNull();
    expect(
      s.ssh.calls.find((c) => c.stdin.includes("termix_change"))?.stdin,
    ).toContain("--on-active=30s");
    const undo = await s.request("POST", "/1/pending/undo");
    expect(undo.body.state).toBe("reverted");
    expect((await s.request("POST", "/1/pending/keep")).status).toBe(404);
  });

  it("drops a pending change the host no longer has", async () => {
    const s = await start();
    await s.request("POST", "/1/enable", { allowSsh: true });
    const status = await s.request("GET", "/1/status");
    expect(status.body.pending).toBeNull();
  });

  it("reports a change that failed and was put back", async () => {
    const s = await start();
    s.ssh.replies.unshift({
      match: "termix_change()",
      stdout: "@@armed@@\nSCRIPT_ERR:UFW refused the rule\n@@reverted@@\n",
      code: 1,
    });
    const res = await s.request("POST", "/1/defaults", { incoming: "deny" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("UFW refused the rule. Nothing was changed.");
    expect((await s.request("GET", "/1/pending")).body.pending).toBeNull();
    expect(s.mock.audits.at(-1)).toMatchObject({
      action: "firewall.defaults",
      success: false,
    });
  });

  it("uses the timer for every change when asked", async () => {
    const s = await start({ hostSettings: { confirmAll: true } });
    const res = await s.request("POST", "/1/rules", {
      protocol: "tcp",
      port: "8080",
    });
    expect(res.body.pending).not.toBeNull();
  });

  it("refuses to ban the Termix address unless forced", async () => {
    const s = await start();
    const self = await s.request("POST", "/1/fail2ban/ban", {
      jail: "sshd",
      ip: "10.0.0.5",
    });
    expect(self.status).toBe(409);
    const other = await s.request("POST", "/1/fail2ban/ban", {
      jail: "sshd",
      ip: "203.0.113.7",
    });
    expect(other.status).toBe(200);
    expect(s.ssh.calls.at(-1)?.stdin).toContain(
      "fail2ban-client set 'sshd' banip '203.0.113.7'",
    );
    expect(
      (
        await s.request("POST", "/1/fail2ban/ban", {
          jail: "a;b",
          ip: "1.2.3.4",
        })
      ).status,
    ).toBe(400);
  });

  it("only installs known tools", async () => {
    const s = await start();
    expect(
      (await s.request("POST", "/1/install", { what: "netcat" })).status,
    ).toBe(400);
    const ok = await s.request("POST", "/1/install", { what: "fail2ban" });
    expect(ok.status).toBe(200);
    expect(s.ssh.calls.at(-1)?.stdin).toContain(
      "apt-get install -y -qq fail2ban",
    );
  });

  it("saves watches", async () => {
    const s = await start();
    expect((await s.request("GET", "/1/watch")).body.on).toBe(false);
    await s.request("PUT", "/1/watch", { on: true });
    expect((await s.request("GET", "/1/watch")).body.on).toBe(true);
    const summary = await s.request("GET", "/summary");
    expect(summary.body[0]).toMatchObject({
      hostId: 1,
      backend: "ufw",
      active: true,
      rules: 2,
      watched: true,
    });
  });
});

describe("rule sets", () => {
  it("creates, checks and applies a set", async () => {
    const s = await start();
    const created = await s.request("POST", "/rulesets", {
      name: "Web server",
      rules: [
        { protocol: "tcp", port: "443,80" },
        { protocol: "tcp", port: "8443" },
      ],
      hosts: [1],
    });
    expect(created.status).toBe(200);
    expect(created.body).toMatchObject({ name: "Web server", hosts: [1] });
    const id = created.body.id;

    const drift = await s.request("GET", `/rulesets/${id}/drift`);
    expect(drift.body[0].missing).toHaveLength(1);
    expect(drift.body[0].missing[0].port).toBe("8443");

    const applied = await s.request("POST", `/rulesets/${id}/apply`, {});
    expect(applied.body[0]).toMatchObject({ hostId: 1, added: 1, kept: true });
    const arm = s.ssh.calls.find((c) => c.stdin.includes("termix_change"));
    expect(arm?.stdin).toContain("port 8443");
    expect(arm?.stdin).not.toContain("port 80,443");
    expect(s.ssh.calls.some((c) => c.stdin.includes('echo "state=kept"'))).toBe(
      true,
    );

    const list = await s.request("GET", "/rulesets");
    expect(list.body).toHaveLength(1);
    await s.request("PUT", `/rulesets/${id}`, {
      name: "Web",
      rules: [],
      hosts: [],
    });
    expect((await s.request("GET", "/rulesets")).body[0]).toMatchObject({
      name: "Web",
      hosts: [],
    });
    expect((await s.request("DELETE", `/rulesets/${id}`)).status).toBe(200);
    expect((await s.request("GET", "/rulesets")).body).toHaveLength(0);
  });

  it("keeps sets per user and checks their input", async () => {
    const s = await start();
    expect((await s.request("POST", "/rulesets", { name: "" })).status).toBe(
      400,
    );
    expect(
      (
        await s.request("POST", "/rulesets", {
          name: "x",
          rules: [{ port: "nope" }],
        })
      ).status,
    ).toBe(400);
    const created = await s.request("POST", "/rulesets", { name: "Mine" });
    s.mock.setActor("user-2");
    expect((await s.request("GET", "/rulesets")).body).toHaveLength(0);
    expect(
      (await s.request("DELETE", `/rulesets/${created.body.id}`)).status,
    ).toBe(404);
  });

  it("lists no fleets without the Fleets plugin", async () => {
    const s = await start();
    expect((await s.request("GET", "/fleets")).body).toEqual([]);
  });
});
