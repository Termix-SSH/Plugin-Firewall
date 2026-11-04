import { describe, expect, it } from "vitest";
import {
  normalizePorts,
  parseAddress,
  parsePorts,
  parseRuleSpec,
  portsCover,
  requireComment,
  requireIp,
  requireJail,
  specKey,
} from "../../src/backend/validate";

describe("ports", () => {
  it("reads single ports, lists and ranges", () => {
    expect(parsePorts("22")).toEqual([{ from: 22, to: 22 }]);
    expect(normalizePorts("443, 80")).toBe("80,443");
    expect(normalizePorts("8100:8200")).toBe("8100-8200");
    expect(parsePorts("")).toEqual([]);
  });

  it("refuses bad ports", () => {
    for (const bad of [
      "0",
      "65536",
      "22;rm",
      "a-b",
      "100-50",
      "1-2-3",
      "22 23",
    ]) {
      expect(() => parsePorts(bad), bad).toThrow();
    }
    expect(() =>
      parsePorts(Array.from({ length: 16 }, (_, i) => String(i + 1)).join(",")),
    ).toThrow(/15/);
  });

  it("knows what a list covers", () => {
    expect(portsCover("", 22)).toBe(true);
    expect(portsCover("20-30", 22)).toBe(true);
    expect(portsCover("80,443", 22)).toBe(false);
    expect(portsCover("junk", 22)).toBe(false);
  });
});

describe("addresses and names", () => {
  it("accepts addresses and ranges", () => {
    expect(parseAddress("10.0.0.0/8")).toBe("10.0.0.0/8");
    expect(parseAddress("2001:DB8::/32")).toBe("2001:db8::/32");
    expect(parseAddress("any")).toBe("");
    for (const bad of [
      "10.0.0.0/33",
      "10.0.0",
      "example.com",
      "1.2.3.4/8/9",
      "$(id)",
    ]) {
      expect(() => parseAddress(bad), bad).toThrow();
    }
  });

  it("checks comments, jails and IPs", () => {
    expect(requireComment("web server")).toBe("web server");
    for (const bad of ['a"b', "a'b", "a\\b", "a$b", "a\nb", "x".repeat(121)]) {
      expect(() => requireComment(bad), bad).toThrow();
    }
    expect(requireJail("sshd")).toBe("sshd");
    expect(() => requireJail("a b")).toThrow();
    expect(requireIp("203.0.113.7")).toBe("203.0.113.7");
    expect(() => requireIp("203.0.113.0/24")).toThrow();
  });
});

describe("rule specs", () => {
  it("fills defaults and works out the family", () => {
    expect(
      parseRuleSpec({ port: "22", protocol: "tcp", source: "::1" }),
    ).toMatchObject({
      action: "allow",
      direction: "in",
      family: "ipv6",
      port: "22",
    });
  });

  it("refuses mixed or bad input", () => {
    expect(() => parseRuleSpec({ action: "explode" })).toThrow();
    expect(() => parseRuleSpec({ port: "80,443" })).toThrow(/tcp or udp/);
    expect(() =>
      parseRuleSpec({ source: "10.0.0.1", destination: "::1" }),
    ).toThrow(/both/);
    expect(() => parseRuleSpec({ source: "10.0.0.1", family: "ipv6" })).toThrow(
      /family/,
    );
    expect(() =>
      parseRuleSpec({ service: "http", port: "80", protocol: "tcp" }),
    ).toThrow(/not both/);
    expect(() => parseRuleSpec({ iface: "eth0; reboot" })).toThrow();
  });

  it("gives the same key to rules that do the same thing", () => {
    const a = parseRuleSpec({ port: "443,80", protocol: "tcp", comment: "a" });
    const b = parseRuleSpec({ port: "80,443", protocol: "tcp", comment: "b" });
    expect(specKey(a)).toBe(specKey(b));
    expect(specKey(a)).not.toBe(
      specKey(parseRuleSpec({ port: "80,443", protocol: "udp" })),
    );
  });
});
