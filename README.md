<div align="center">

<img src="https://termix.site/img/logo.svg" width="120" alt="Termix Logo" />

<h1>Firewall</h1>

<p>Manage UFW, firewalld, nftables and iptables rules on your hosts over SSH, with lockout protection</p>

<!-- VIDEO:START -->
<!-- VIDEO:END -->

</div>

<br />

## Overview

Firewall manages the firewall on your hosts over SSH. Each host gets a tab for its rules, default policies, firewalld zones and Fail2ban. Termix checks every change for an SSH lockout first, and risky changes undo themselves on the host unless you press Keep.

Read the [docs](https://docs.termix.site/plugins/firewall) to set it up and use it.

<br />

## Features

- UFW, firewalld, nftables and iptables
- Add, edit and delete rules, set defaults and firewalld zones
- Turn the firewall on or off, or install one
- SSH lockout check and an undo timer that runs on the host
- Rule sets for many hosts or a fleet, with a drift check
- Fail2ban jails, bans and unbans
- Alerts when a firewall turns off or changes outside Termix
- A firewall panel beside SSH terminals and a dashboard card
- Roll out a port across hosts and watch it for drift in Operations Center

<br />

## Sponsors

For a paid sponsor spot, email [mail@termix.site](mailto:mail@termix.site).

<!-- SPONSORS:START -->

<div align="center">

<br />

<a href="https://www.blacksmith.sh/">
  <img src="https://termix.site/img/sponsors/blacksmith.svg" height="40" alt="Blacksmith" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://www.cloudflare.com/">
  <img src="https://termix.site/img/sponsors/cloudflare.png" height="40" alt="Cloudflare" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://akamai.com/">
  <img src="https://termix.site/img/sponsors/akamai.svg" height="40" alt="Akamai" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://aws.amazon.com/">
  <img src="https://termix.site/img/sponsors/aws.png" height="40" alt="AWS" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://rackgenius.com/">
  <img src="https://termix.site/img/sponsors/rackgenius.png" height="40" alt="Rack Genius" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://ginernet.com/">
  <img src="https://termix.site/img/sponsors/ginernet.png" height="40" alt="Ginernet" />
</a>
&nbsp;&nbsp;&nbsp;
<a href="https://www.hetzner.com/?mtm_campaign=termix&mtm_medium=referral&mtm_content=sponsoring_link">
  <img src="https://termix.site/img/sponsors/hetzner.png" height="40" alt="Hetzner" />
</a>

</div>

<!-- SPONSORS:END -->

<br />

## Support

Bugs and ideas for Firewall go in this repo: [report a bug](https://github.com/Termix-SSH/Plugin-Firewall/issues/new?template=bug_report.yml) or [request a feature](https://github.com/Termix-SSH/Plugin-Firewall/issues/new?template=feature_request.yml). Report an issue on the plugin's page in the Plugins tab fills in your versions for you.

Problems with Termix itself (login, hosts, credentials, sharing, sync) go in the [Termix repo](https://github.com/Termix-SSH/Termix/issues/new/choose). Not sure where it goes? Open it there and it will be moved.

Add as much detail as you can, in English if possible. For questions, join the [Discord](https://discord.gg/jVQGdvHDrf) server.

<br />

## License

Apache License 2.0. See [LICENSE](LICENSE).
