# vibecodingnonsense
For other people who want to save time vibecoding and use templates of stuff I had claude code for days

## Templates

### [`staff-portal/`](staff-portal/) — staff access, audit and streak dashboard

A company's private front door, on Cloudflare Workers + D1, with no runtime
dependencies. It merges two designs into one dashboard:

- **🔥 Calendar-aware sign-in streaks.** A 30-hour rolling window. The clock
  stops for Shabbos and Yom Tov, which come from an arithmetic Hebrew calendar
  checked against ICU, or for any weekly days or closure dates you configure.
  You get re-entry grace after each block, and there is a hard cap that a
  calendar bug can't get past.
- **Who works here:** ranked roles, permissions that can never be granted
  (only the Super Admin holds them), invitations, access requests and employee
  numbers.
- **How they sign in:** a password, then a passkey, an authenticator app, a
  backup code, or a texted/emailed code as a fallback. Trusted networks get
  grace windows, and nobody can lock themselves out.
- **From where:** an IP allowlist and blocklist, six access modes, device
  approval, country/Tor/datacenter/automation rules, and a browser fingerprint
  with a risk score where every point has a reason.
- **What they did:** a hash-chained audit log that can be verified and
  reverted.

Start with [`staff-portal/README.md`](staff-portal/README.md). The full
design and its lessons are in [`staff-portal/SPEC.md`](staff-portal/SPEC.md).
