/** firewall-cmd --list-all-zones output, as firewalld 2 prints it. */
export const ZONES = `block
  target: %%REJECT%%
  interfaces:
  sources:
  services:
  ports:

public (default, active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: dhcpv6-client ssh
  ports: 8080/tcp 60000-61000/udp
  protocols:
  forward: yes
  masquerade: no
  rich rules:
	rule family="ipv4" source address="203.0.113.0/24" drop
	rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept
	rule family="ipv4" source address="10.0.0.0/8" log prefix="x" accept

trusted (active)
  target: ACCEPT
  interfaces:
  sources: 10.8.0.0/24
  services:
  ports:
`;

export const FIREWALLD_SECTIONS = {
  "fwd-version": "2.3.1",
  "fwd-default": "public",
  "fwd-zones": ZONES,
  "fwd-services": "dhcpv6-client=546/udp\nssh=22/tcp",
};
