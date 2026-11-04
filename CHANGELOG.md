# Changelog

## 1.0.0

### Added

- A Firewall tab for each host to manage UFW, firewalld, nftables and iptables over SSH
- Add, edit and delete rules, set the default policies and firewalld zones
- Turn the firewall on or off, and install UFW, firewalld, nftables or Fail2ban
- An SSH lockout check before changes that could cut off Termix
- Risky changes undo themselves on the host unless you press Keep
- Rule sets to add the same rules to many hosts or a fleet, with a drift check
- Fail2ban jails, banned addresses, ban and unban
- Alerts when a firewall turns off or its rules change outside Termix
- A firewall panel beside SSH terminals and a dashboard card for every host
