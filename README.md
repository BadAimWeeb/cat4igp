## CAT4IGP - Controllable Array of Tunnels for Interior Gateway Protocol

This is inspired by [RAIT](https://gitlab.com/NickCao/RAIT), which is a piece of software that if given a registry, will create a bunch of "inexpensive" WireGuard tunnels. You can abuse those as a bunch of point-to-point link and run IGP like Babel to figure out best routes.

While it is great, it has some drawbacks:

- It does not have a daemon and therefore cannot do tricks like UDP hole-punching.
- It also requires a cron job to automatically update new link, or you have to manually go to each node and refresh it.
- You cannot easily control which links are created, only a full-mesh networks can be formed. The amount of tunnels will be ridiculously high if you have a large amount of nodes, and you may not be able to handle it.
- The binary size of it is large due to usage of Golang (although I don't know if I can optimize Rust to be more efficient...)
- You can only use WireGuard. I'd like to add more types of tunnel, and the capability to do tunnel over tunnel (e.g. L2TP over WireGuard, with IP fragmentation inside WireGuard to get a very high MTU capable of transmitting jumbo frames)

This will attempt to address those drawbacks.

**WORK-IN-PROGRESS**

**This is not available in Windows.**
