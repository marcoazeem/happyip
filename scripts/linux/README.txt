HappyIP for Linux
=================

Run it straight from this folder:

    ./happyip

or install it for your user (menu entry, icon, ~/.local/bin/happyip):

    ./install.sh

Needs a desktop session (X11 or Wayland) and glibc 2.35 or newer
(Ubuntu 22.04, Debian 12, Fedora 36 and later).

For the best results also have these installed; most systems already do:

    ping        (iputils-ping)   finds devices that answer ping
    ip          (iproute2)       MAC addresses and IPv6 neighbours
    curl                         in-app updates
    xdg-open    (xdg-utils)      opens reports, web pages, ssh:// and smb:// links

Without a window (servers, SSH sessions):

    ./happyip --cli 192.168.1.0/24
    ./happyip --cli --help
    ./happyip --update

Only scan networks you own or are authorized to scan.
