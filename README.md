Zyxel GS1900
============

API to monitor Zyxel GS1900 switches using SSH and control some
features via HTTP. This is required, since the SNMP interface of
those switches is quite limited, the SSH (and Telnet) interface
is basically read-only and the HTTP interface provides less
information than the SSH interface (and hard to implement, since
it does not follow standards properly).

Since HTTP is only required for write-access and pulls in quite
a few dependencies, support is optional and can be disabled by
unselecting the "web" feature from this crate.

Tested Devices:
 * Zyxel GS1900-10HP
 * Zyxel GS1900-24

SSH Features:
 * Basic information ("show info")
 * LLDP neighbor information ("show lldp neighbor")
 * Fiber Transceiver ("show fiber-transceiver interfaces all")
 * MAC address table ("show mac address-table")
 * lookup MAC address ("show mac address-table <mac>")
 * lookup MAC table for one port ("show mac address-table interfaces <port>")
 * Cable Diagnosis ("show cable-diag interfaces all")
 * Cable Diagnosis for one port ("show cable-diag interfaces <port>")
 * PoE information ("show power inline consumption")
 * PoE debug info ("debug ilpower port status")
 * traffic information ("show interfaces all")
 * traffic information for one port ("show interfaces <port>")
 * auto-negotiated interface status ("show interfaces all status")
 * VLAN information ("show vlan")
 * nop command for keepalive (sends newline)

Web Features:
 * Control PoE status (enable / disable)
 * Control port status (enable/disable)

License
=======

© 2020 Sebastian Reichel

ISC License

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted, provided that the
above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
