# Recovering the Wii Party U NEX access key

The access key is **`a5b77314`**.

## Why brute force

Wii Party U's main RPX (`nexpy.rpx`) imports `nn_olv.rpl` but **no `nex.rpl`**,
and the 8-char access key is not present as a plaintext string anywhere in the
decompressed binary (unlike some other Wii U titles). Static analysis alone
does not find it, so it was recovered from network traffic instead.

## Method

1. **Capture a real handshake.** Point the console's NEX host at a machine
   running `cmd/capture` (a raw UDP listener, no protocol parsing). Trigger
   the Notes tab so the console sends its PRUDPv1 `CONNECT` (SYN) packet and
   record the raw datagram.

2. **Brute force the signature.** `nex-go`'s
   `defaultPRUDPv1CalculateSignature` is HMAC-MD5 with:
   - key = `MD5(accessKey)`
   - message = `header[4:]` + `sessionKey` (empty on SYN) +
     `accessKeySum` (sum of the access-key ASCII bytes, little-endian uint32) +
     `connectionSignature` (empty on SYN) + `options` + `payload`

   `cmd/bruteforce` recomputes that HMAC for every 8-character lowercase-hex
   candidate (`16^8` ≈ 4.3 billion) and compares against the captured
   packet's signature field. On 16 cores this finishes in ~6.5 minutes.

The captured bytes baked into `cmd/bruteforce/main.go` are one sample SYN;
swap in your own capture (header tail, options, payload, target signature)
to reproduce.

## Notes

- A PRUDPv1 SYN carries no PID or account data — it is a connection
  handshake only.
- `PRUDPV1Settings.LegacyConnectionSignature` must be **`false`** for this
  title. The MH3U-style `true` makes the client reject the CONNECT-ACK and
  retry forever (WiiU error 106-0502).
