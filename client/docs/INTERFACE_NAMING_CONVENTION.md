# cat4igp Unix interface naming convention

cat4igp use a prefix `cat` followed with [Crockford's Base32](https://en.wikipedia.org/wiki/Base32#Crockford's_Base32) 56-bit data for all network interfaces it creates. This will be useful should external tools want to identify cat4igp interfaces, their underlying protocols and their capabilities, to be able to make informed routing decisions.

The following are the current conventions:

```
Protocol type (5 bits) + Peer node id (15 bits) + Protocol-specific data (36 bits)
```

## Protocol Type

Protocol type uses 5 bits (equals a single readable character in Base32) predefined values as follows:

| Printable character | Binary representation | Protocol type       | Notes  |
| ------------------- | --------------------- | ------------------- | ------ |
| `0`                 | `00000`               | OpenVPN             | Alternative for L2TP over WireGuard, and suitable for true TCP-only network. Acceleration may also be available due to usage of standard TLS. |
| `2`                 | `00010`               | L2TP over WireGuard | Use WireGuard as encryption layer, then apply L2TP with fragmentation to get high MTU. Can be used to transparently forward jumbo frames, or full 1500 byte Ethernet MTU. |
| `N`                 | `10101`               | NaïveProxy          | A protocol that uses Chromium network stack to circumvent censorship, masquerading traffic as normal browser. |
| `Q`                 | `10111`               | MASQUE              | Proxying protocol over QUIC, currently used by Cloudflare WARP. This does require port 443 to be open on one side to be effective in bypassing strict network environments (if QUIC is allowed to passthrough for HTTP/3). |
| `W`                 | `11100`               | WireGuard           | |
| `X`                 | `11101`               | 2nd level expansion | Reserved for expandability for lesser-used protocols. |
| `Z`                 | `11111`               | Experimental        | Used for testing new protocols and features before assigning them a specific character. Do not treat protocol-specific data as stable or permanent, check which experimental protocol is in use first. |

## Lesser used protocols

These protocols are implemented under the `X` protocol type to relieve pressure on the limited 5-bit protocol type space. By using 5 to 15 bits inside the protocol-specific data, we can have up to 8464 lesser-used protocols. Consquenently, these protocols may not have enough space for protocol-specific data, and may need to rely on out-of-band communication with the server to obtain necessary information.

If an protocol does not require a lot of protocol-specific data, 15-bit length should be used to reserve more space for future protocols, if not possible or the protocol want to reserve more space for future protocol-specific data, 10-bit and 5-bit length should be used.

Variable length of bits are accomplished per block of 5 bits, max limit are 3 blocks (15 bits). Except for the last block (3rd block), each block must start with `1` bit to indicate there are more blocks to read, and the last block must start with `0` bit to indicate the end of the variable length protocol type. The last block can use all 5 bits for protocol type.

Example:

- `0XXXX` - 5-bit protocol type, no variable length block
- `1XXXX 0YYYY` - 10-bit protocol type, 8 bits for protocol type
- `1XXXX 1YYYY ZZZZZ` - 15-bit protocol type, 13 bits for protocol type

The following are the currently defined protocols:

| Printable characters | Binary representation | Protocol type       | Notes  |
| -------------------- | --------------------- | ------------------- | ------ |
| `XT2`                | `11101 11010 00010`   | L2TP                | NOT RECOMMENDED TO RUN DIRECTLY ON PUBLIC NETWORKS. This protocol is intended to run over another type of tunnel to provide jumbo frames with the use of PPP medium-agnostic properties. |
| `Z?`                 | `11111 0????`         | Experimental        | Used for testing new protocols and features before assigning them a specific character. Do not treat protocol-specific data as stable or permanent, check which experimental protocol is in use first. |
| `Z??`                | `11111 1???? ?????`   | Experimental        | Used for testing new protocols and features before assigning them a specific character. Do not treat protocol-specific data as stable or permanent, check which experimental protocol is in use first. |

## UDP-based protocols: Forward Error Correction (FEC) and FakeTCP support

cat4igp includes support for [UDPspeeder](https://github.com/wangyu-/UDPspeeder), a tunnel layer that will add Forward Error Correction (FEC) to UDP-based protocols to improve performance on lossy networks. 

[FakeTCP](https://github.com/wangyu-/udp2raw) is also supported, to work around the issue of UDP traffic being throttled or blocked on certain networks. However, since FakeTCP is not a true TCP implementation and may not be compatible with all network environments, users should be aware of its limitations and potential issues when using it.

Protocol that is not designed to circumvent censorship and are UDP-based (QUIC-based are exempt) should add a flag to allow for FEC and FakeTCP implementation & indication.
