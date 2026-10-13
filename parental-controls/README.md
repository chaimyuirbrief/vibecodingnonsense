# Parental controls for your own kids' PCs — a DIY starter kit

Use your own Claude (Claude Code, or any Claude chat that can write files) to build a small script that
enforces the rules **you** pick for a computer your kids use: a bedtime cutoff, daily screen-time limit,
blocked sites or apps, and a log of what it did. Nothing here is specific to one family or one machine.
You describe your house rules, Claude writes the script, you test it, you install it.

> **Read this first.** A script like this is a *speed bump*, not a lock. A kid who has admin rights can
> usually get around it. The most effective single step is making the kid's account a **standard
> (non-admin)** account. Run the built-in tools first (see [Start with what's already there](#start-with-whats-already-there));
> use a script only for the gaps those tools leave.

## What this is, and what it isn't

**It is:** a transparent, rules-based enforcement layer on a device you own or administer, that you tell
your kids about, that logs what it does, and that you can remove in a few minutes.

**It isn't:** spyware. Don't use it to read private messages, record keystrokes, take hidden screenshots,
track a kid's location, or hide the fact that it's running from the kid. Those are a different category,
they damage trust, and the prompt below tells Claude to refuse them.

## Before you start

Decide these on paper first. Claude can't guess your family's rules.

1. **Which computer(s)?** Windows, macOS, Linux, or a mix. Each needs different code.
2. **Which account does the kid use?** Ideally a standard account, with a separate admin account that only
   you use. Keep the admin password somewhere safe.
3. **Your rules, written as plain sentences.** For example:
   - No computer use between 9:00 pm and 7:00 am on school nights.
   - 90 minutes per day on weekdays, 3 hours on weekends.
   - Block these sites: ____. Block these apps: ____.
   - Always allow: school portal, the learning app, a calculator, the settings to change the password.
4. **Your kid's age.** Rules for an 8-year-old and a 16-year-old should differ, and the kid should know
   what the rules are and why.
5. **A test machine or a spare account.** Never first-test on the machine your kid is currently using.
   A virtual machine (VirtualBox, UTM, Hyper-V) is ideal.

## Paste-ready prompt

Open a Claude Code session in an empty folder on **your own** computer (or your own repo), then paste the
block below. Fill in the `<<...>>` parts first.

````text
I want a small, transparent parental-control script for a computer my child uses. I own this computer
and I'm the parent/guardian. Help me build it step by step and keep it simple enough that I can read
every line.

Setup facts:
- Operating system of the kid's computer: <<Windows 11 / macOS 14 / Ubuntu 24.04 / other>>
- The kid's account name: <<name>>  (it is a standard, non-admin account: yes / no)
- Kid's age: <<age>>
- Rules, in my words: <<paste your rules from the list above>>
- Time zone: <<e.g. America/New_York>>
- Sites to block (domains): <<list>>
- Apps to block (executable names): <<list>>
- Always-allowed items: <<list>>

Build it like this:
1. Ask me at most three clarifying questions before writing code, then go.
2. Use only the OS's built-in tools: Task Scheduler + PowerShell (Windows), launchd + bash (macOS),
   or systemd timers + bash (Linux). No third-party agents, no downloads of unknown binaries.
3. Put all rules in one config file (rules.json or rules.yaml) so I can change limits without editing code.
4. Enforce, at minimum: a bedtime cutoff (end the session with a warning first, e.g. 5 minutes),
   a daily time budget that resets at a set hour, and a blocklist for sites (hosts-file entries) and apps.
   Use the normal OS log-out or close mechanism, not a kernel hack.
5. Write a log file of every action the script takes (time, rule, action). Keep the log readable by me.
   Do not record keystrokes, page contents, screenshots, or messages. Ever.
6. Write an install script and an uninstall script. Uninstall must fully restore the original state:
   remove scheduled tasks, remove the hosts-file entries it added (only those, by marker), and delete
   the files it created. Test that uninstall undoes install.
7. Write a TEST.md with a checklist I run in a VM or on a spare account before installing for real:
   - the warning appears before the cutoff
   - the session ends at the cutoff and cannot be extended by the kid
   - blocked sites fail to load in Chrome, Firefox, and Edge (or Safari on macOS)
   - allowed items still work, including logging out, the calculator, and the school portal
   - the parent admin account still works and can change settings
   - uninstall restores everything
8. Include a README.md for me: what it does, what it can't do, how to change rules, how to uninstall,
   and how to tell the kid about it.

Hard rules for the code you write:
- Never block the parent/admin account, the admin password reset path, or emergency calls.
- Never make the machine unbootable or require a reinstall to undo. Every change must be reversible.
- No silent installs, no hidden processes or hidden files meant to conceal the script from the kid.
  The script must show up in the normal list of startup items and scheduled tasks, so I can see it.
- Don't store the kid's data anywhere except the local log file, and don't send anything over the network.
- Don't implement covert monitoring, keylogging, screenshot capture, message reading, location tracking,
  or anything that works around the kid's privacy in a way they'd object to if they knew. If I ask for
  that, say no and suggest an open, age-appropriate alternative.
- Prefer rules that are easy to explain to the kid. Warn me about any rule that would be hard to justify.
- Be honest in the README about the bypasses that remain (for example a kid with admin rights, a
  browser using DNS-over-HTTPS, a phone or another device). Don't overclaim.

Start by confirming my setup facts back to me in a short list, then ask your clarifying questions.
````

## Start with what's already there

Before writing anything, check whether a built-in tool does the job. They're easier to maintain and harder
to bypass than a custom script:

| Device | Built-in option |
|---|---|
| Windows | Microsoft Family Safety (or local "Family" settings) for time limits, web and app filters |
| macOS / iPad / iPhone | Screen Time (Downtime, App Limits, Content & Privacy) |
| Android / Chromebook | Google Family Link |
| Home network | Router parental controls, or a DNS filter such as your router's or a family-filter DNS service |

A custom script earns its place when you want a rule the built-ins can't express, or you want full
control and visibility over exactly what runs.

## Guardrails for whoever runs this

- **Tell your kid.** Explain the rules, the reason for each, and that the script is on the machine.
  Enforcement that the kid knows about lasts longer than enforcement they discover.
- **Revisit the rules.** Review them every few months. Loosen them as your kid shows good judgment.
- **Keep the admin password** somewhere only you can reach.
- **Test before you install**, every time you change the rules.
- **Keep the uninstall script** and confirm it works before you need it.
- **Don't use this on someone else's computer** (a partner's, a roommate's, an employee's) without their
  knowledge and agreement.

## Known limits

- An admin user can stop a script, edit the hosts file, or reinstall the OS. Standard accounts close most of this.
- Browsers with DNS-over-HTTPS or a VPN can bypass hosts-file blocking. Block those too, or use a
  router-level filter.
- A phone, tablet, or a friend's computer isn't covered by a script on one PC.
- Time limits based on wall-clock time can be defeated by changing the clock. Standard accounts and an
  NTP-synced clock make this harder.

## Not legal advice

Rules about monitoring and what you may do on a device differ by country and by who owns the device. If
you're unsure, check your local rules, and ask an adult you trust. This guide is about helping a parent
set up reasonable, transparent limits, not a substitute for that check.

## Sharing

Found this useful? Share the link to this folder. Anyone can paste the prompt above into their own Claude
and get a version built for their own kids, devices, and rules.
