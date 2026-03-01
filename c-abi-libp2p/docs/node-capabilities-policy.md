# Node Capabilities and Role Policy (Single-Device Stage)

This document consolidates node-role flags for the current protocol stage.

Current stage goal:

- treat each profile/device as an independent peer endpoint,
- defer account-level multi-device fanout and device-directory logic,
- keep relay behavior explicit and simple.

## 1. What exists in the core now

In `c-abi-libp2p` runtime/core:

- `use_quic` (transport toggle)
- `hop_relay` (enable relay server behavior)
- AutoNAT status stream (`unknown/private/public`)
- relay client behavior (for dialing through relays)

In CLI examples:

- role intent (`relay` or `leaf`)
- optional `--force-hop`
- AutoNAT-driven restart path to enable hop relay after public reachability

## 2. What is intentionally not in core yet

- no mailbox storage role in protocol
- no node class markers (`mobile/desktop/server`) in protocol
- no relay descriptor registry/capability advertisement
- no relay reputation/ranking model in protocol
- no super-relay authorization certificates in protocol

## 3. Recommended minimal role model for this stage

Use only two effective runtime modes:

- `leaf`: relay server disabled (`hop_relay=false`)
- `relay`: relay server enabled (`hop_relay=true`)

Selection rule:

- default to `leaf`
- enable `relay` only by explicit user opt-in (and optionally AutoNAT public gate)

## 4. Which node traits are needed now vs later

Needed now:

- `hop_relay` (yes)
- `autonat_status` (yes)
- user opt-in flag for serving relay traffic (yes)

Not needed now (defer):

- `mobile/desktop/server` labels
- `routing-only` vs `mailbox` capability bit
- relay storage quota declarations
- relay score/reputation
- super-relay trust governance

## 5. Future extension path (when mailbox is implemented)

When offline mailbox is introduced, add protocol-level descriptors:

- `relay_capabilities.routing` (bool)
- `relay_capabilities.mailbox` (bool)
- `mailbox_limits` (quota, ttl)
- optional `node_class` hint (not trusted by itself)

Add governance only after that:

- super-relay certificates signed by pinned developer root keys,
- revocation lists,
- policy-based placement across relay classes.

