# Wii Party U DataStore tags (Notes tab)

The in-game **Notes** tab is a star-rating feature. When it opens, the
console runs a full PRUDPv1 NEX session (auth + secure) and bootstraps the
screen with `DataStore::SearchObject`, then `GetRatings`, then `RateObject`
when the player submits a rating.

Known search tags (from community notes, e.g. ItzSwirlz's HackMD):

| Tag    | Meaning                    |
|--------|----------------------------|
| `npg`  | main-game ratings          |
| `nmg`  | minigame ratings           |
| `mira` | "Amazing Feats" records    |

## Current server behaviour

This is a bring-up implementation, not a full DataStore:

- `SearchObject` returns **one placeholder** `DataStoreMetaInfo` (DataID 1,
  owned by the caller, tagged with whatever the client searched for) with
  `TotalCount = 1`. A genuinely empty result (`TotalCount = 0`) makes the
  retail client bounce straight back out of the Notes screen, even though
  that same "empty but successful" shape is accepted by other titles.
- `GetRatings` returns "unrated" (count 0) for every requested DataID unless
  a rating has been submitted this session.
- `RateObject` accumulates into an **in-memory** store (`dataID`+`slot` →
  total/count), so a submitted rating is reflected back but does not survive
  a restart.

Real per-tag data and a database backing are still to do.
