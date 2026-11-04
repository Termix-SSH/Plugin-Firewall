import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

const baseRule = {
  direction: "in",
  protocol: "tcp",
  source: "",
  destination: "",
  iface: "",
  family: "any",
  comment: "",
  managed: true,
  raw: "",
};

const status = {
  backend: "ufw",
  installed: ["ufw", "nftables"],
  active: true,
  version: "ufw 0.36.2",
  defaults: { incoming: "deny", outgoing: "allow", routed: "deny" },
  rules: [
    { ...baseRule, id: "a", action: "allow", port: "22" },
    {
      ...baseRule,
      id: "b",
      action: "deny",
      port: "",
      source: "203.0.113.0/24",
      protocol: "any",
    },
    {
      ...baseRule,
      id: "c",
      action: "allow",
      port: "",
      protocol: "any",
      managed: false,
      readOnlyReason: "Routed rules can't be changed here yet",
    },
  ],
  zones: [],
  defaultZone: "",
  otherRules: 0,
  persistent: true,
  warnings: [],
  ssh: { ports: [22], client: "10.0.0.5" },
  packageManager: "apt-get",
  os: "Debian",
  root: true,
  fail2ban: { installed: false, running: false },
  canEdit: true,
  readOnly: false,
  sshGuard: true,
  pending: null,
};

function api(current: unknown, overrides: Record<string, unknown> = {}) {
  return {
    get: vi.fn(async (url: string) => {
      const path = url.split("?")[0];
      for (const [key, value] of Object.entries(overrides)) {
        if (path.endsWith(key)) return { data: value };
      }
      if (path.endsWith("/status")) return { data: current };
      if (path.endsWith("/watch")) return { data: { on: false } };
      return { data: [] };
    }),
    post: vi.fn(async () => ({ data: { ok: true, pending: null } })),
    put: vi.fn(async () => ({ data: { ok: true, pending: null } })),
    delete: vi.fn(async () => ({ data: { ok: true, pending: null } })),
  } as never;
}

const host = {
  id: 1,
  name: "box",
  ip: "10.0.0.1",
  enableSsh: true,
  pluginSettings: { firewall: { enableFirewall: true } },
};

describe(`${manifest.id} frontend`, () => {
  it("registers both tabs and the dashboard card", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.tabs()).toEqual([
      "firewall",
      "firewall-rulesets",
    ]);
    expect(rendered.registered.dashboardCards()).toEqual(["firewall-hosts"]);
  });

  it("only offers the tab and panel on hosts that turned it on", () => {
    expect(plugin.firewallEnabled(host)).toBe(true);
    expect(plugin.firewallEnabled({ pluginSettings: {} })).toBe(false);
    expect(plugin.firewallPanelEnabled(host)).toBe(true);
    expect(
      plugin.firewallPanelEnabled({
        pluginSettings: {
          firewall: { enableFirewall: true, showPanel: false },
        },
      }),
    ).toBe(false);
  });

  it("lists the rules with read only ones marked", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api(status),
    });
    rendered.renderTab("firewall", { isVisible: true, host });
    expect(await screen.findByText("tcp 22")).toBeTruthy();
    expect(screen.getByText(/from 203\.0\.113\.0\/24/)).toBeTruthy();
    expect(screen.getAllByText(locales.rules.readOnly).length).toBeGreaterThan(
      0,
    );
    expect(screen.getByText(locales.rules.add)).toBeTruthy();
  });

  it("opens the rule editor", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api(status),
    });
    rendered.renderTab("firewall", { isVisible: true, host });
    fireEvent.click(await screen.findByText(locales.rules.add));
    expect(await screen.findByText(locales.rules.addTitle)).toBeTruthy();
    expect(screen.getByText(locales.presets.https)).toBeTruthy();
  });

  it("hides changes without edit access", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api({ ...status, canEdit: false }),
    });
    rendered.renderTab("firewall", { isVisible: true, host });
    await screen.findByText("tcp 22");
    expect(screen.queryByText(locales.rules.add)).toBeNull();
    expect(screen.queryByText(locales.disable.button)).toBeNull();
  });

  it("offers to turn the firewall on with SSH allowed", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api({ ...status, active: false }),
    });
    rendered.renderTab("firewall", { isVisible: true, host });
    expect(await screen.findByText(locales.enable.off)).toBeTruthy();
    expect(screen.getByText("Allow SSH on port 22 first")).toBeTruthy();
  });

  it("shows the pending change with Keep and Undo", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api({
        ...status,
        pending: {
          token: "t",
          hostId: 1,
          label: "enable|",
          expiresAt: Date.now() + 45_000,
          reachable: true,
        },
      }),
    });
    rendered.renderTab("firewall", { isVisible: true, host });
    expect(await screen.findByText(locales.pending.kinds.enable)).toBeTruthy();
    expect(screen.getByText(locales.pending.keep)).toBeTruthy();
    expect(screen.getByText(locales.pending.undo)).toBeTruthy();
    expect(screen.queryByText(locales.rules.add)).toBeNull();
  });

  it("offers an install when the host has no firewall", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api({
        ...status,
        backend: null,
        active: false,
        rules: [],
        installed: [],
      }),
    });
    rendered.renderTab("firewall", { isVisible: true, host });
    expect(await screen.findByText(locales.install.none)).toBeTruthy();
    expect(screen.getByText("Install UFW")).toBeTruthy();
  });

  it("says when the host has Firewall turned off", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: {
        get: vi.fn(async () => {
          throw { response: { data: { error: "off", code: "disabled" } } };
        }),
      } as never,
    });
    rendered.renderTab("firewall", { isVisible: true, host });
    expect(await screen.findByText(locales.tab.disabled)).toBeTruthy();
  });
});

describe("firewall hosts card", () => {
  it("lists hosts with their firewall state", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      permissions: ["firewall.use"],
      hosts: [{ id: "1", name: "box", ip: "10.0.0.1", port: 22 }],
      api: {
        get: vi.fn(async () => ({
          data: [
            {
              hostId: 1,
              backend: "ufw",
              active: false,
              rules: 3,
              banned: 2,
              pending: false,
              watched: false,
              checkedAt: new Date().toISOString(),
            },
          ],
        })),
      } as never,
    });
    rendered.renderDashboardCard("firewall-hosts");
    expect(await screen.findByText("box")).toBeTruthy();
    expect(screen.getByText("ufw off")).toBeTruthy();
    expect(screen.getByText("2 banned")).toBeTruthy();
  });
});
