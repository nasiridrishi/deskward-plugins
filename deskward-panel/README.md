# deskward-panel

A pane beside the Claude Code chat for projects that register a `deskward` MCP server. It shows
which computer the project drives (the project's alias and the machine's own name), whether a
session is pending, approved (with the time left), paused or stopped, whether the person is using
that computer right now, whether Deskward's guards are ready, and the agent's recent Deskward
calls, with refusals such as `user_active` or `observe_before_submit` shown by their code.

It reads the server's public status every five seconds, with no session key, and watches the
agent's own Deskward calls. Its only buttons step through the replay below: approving, pausing
and stopping stay physical acts on the computer itself. `/deskward` opens the pane; it also opens by itself once the server answers.
In a project with no `deskward` server it stays closed and asks once a minute.

## Replaying the screen

The pane shows the agent's latest screenshot with what it did since the one before: the rings,
boxes and window outline Deskward draws on its screenshots, a line saying what they mean, and the
agent's other Deskward calls in between, refusals by their code. Back, Next and Latest step
through the last eight. The pane asks Deskward for a small copy of each screenshot (`preview`),
which arrives as a third image beside the agent's own; the agent's image is unchanged. On the
desktop the copy is drawn in an SVG; where a surface leaves pictures out, the marks still show in
outline. The terminal shows the words only.

## Connecting a computer

`/deskward connect <computer>` adds a computer's Deskward to the project, with nothing of
Deskward's installed here; a bare name gets `.local`. On that computer, choose **Paired
computers...** in Deskward's menu and press **Pair**; type the code it shows when asked
(or give it after the name), then press **Confirm** there. macOS then asks for the account
password once, to trust that Deskward's certificate.

The code does the checking. The plugin and Deskward run SPAKE2 keyed by it (the 2048-bit group of
RFC 3526), so the certificate Deskward sends is authenticated by the code: something else on the
network cannot answer in its place without knowing it, and one wrong try uses the code up. The
plugin makes the token it will present and sends only its hash, bound to the exchange, which
Deskward keeps once the person confirms. It then checks, from the certificate's own bytes, that
it is an authority Deskward makes (a critical CA limited by critical name constraints to `local`
and `localhost`, excluding every IPv4 and IPv6 address), so a computer that knows the code but is not a real Deskward
cannot get an unrestricted root trusted; and trusts exactly that certificate in the login
keychain for TLS only, and adds `deskward` with the token as its bearer header, offering to
replace a server already named so. The token is valid while the computer stays paired.

Other systems get the manual steps for now.

## Install

In Claude Code:

```
/plugin marketplace add nasiridrishi/deskward-plugins
/plugin install deskward-panel@deskward
```

or from a shell, `claude plugin marketplace add nasiridrishi/deskward-plugins` and
`claude plugin install deskward-panel@deskward`. Deskward's pairing card shows the same commands.
