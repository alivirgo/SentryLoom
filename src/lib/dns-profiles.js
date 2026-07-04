export const DNS_PROFILES = Object.freeze([
  Object.freeze({
    id: "adguard-default",
    name: "AdGuard DNS",
    description: "Blocks ads and trackers.",
    homepage: "https://adguard-dns.io/en/public-dns.html",
    ipv4: Object.freeze(["94.140.14.14", "94.140.15.15"]),
    ipv6: Object.freeze(["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"]),
    dohTemplate: "https://dns.adguard-dns.com/dns-query",
    recommended: true
  }),
  Object.freeze({
    id: "controld-ads-tracking",
    name: "Control D",
    description: "Blocks malware, ads, and trackers.",
    homepage: "https://docs.controld.com/docs/free-dns",
    ipv4: Object.freeze(["76.76.2.2", "76.76.10.2"]),
    ipv6: Object.freeze(["2606:1a40::2", "2606:1a40:1::2"]),
    dohTemplate: "https://freedns.controld.com/p2",
    recommended: false
  }),
  Object.freeze({
    id: "mullvad-base",
    name: "Mullvad Base DNS",
    description: "Blocks ads, trackers, and malware.",
    homepage: "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls",
    ipv4: Object.freeze(["194.242.2.4"]),
    ipv6: Object.freeze(["2a07:e340::4"]),
    dohTemplate: "https://base.dns.mullvad.net/dns-query",
    recommended: false
  })
]);

export function getDnsProfile(id) {
  return DNS_PROFILES.find((profile) => profile.id === id) || null;
}
