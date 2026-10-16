# IOC backfill: owner review record (Task A3)

Owner review of the `threat_research` / mirror-feed reference backfill. Every row below was decided by the owner on **2026-10-16**; this file is the committed record of what was applied.

## Rulings

### Round 1 (owner, 2026-10-16)

- D1 (a): the 76 HUMAN BADBOX 2.0 rows cite the live HUMAN Satori post with `# verified manually: Claude (A3 research), 2026-10-16, archive.org snapshot 20250509164849` (live page 403s to bots; CI is offline, so no exemption is needed).
- D2 (a): relabel the 25 BITTER rows to ESET's names (superseded for the labels by the controller ruling below). `youtubepremiumapp.com` stays BITTER (Meta Q2-2022, pdftotext).
- D3: Triada ×23 ThreatFox domains → the feed label `Unknown malware`, `feed:threatfox#Unknown malware`.
- D4 (a): replace the shortened stalkerware names by the feed's exact ids (superseded in round 2).
- D5: Mirax Bot ×4 ThreatFox hashes → `Unknown malware`, source threatfox; NFCShare `669b75fd…` removed; the unlabelled MB hashes were held (decided in round 2).
- D6: the 4 bundle-only APK hashes (Cerberus, SpyNote, Vultur, AndrMonitor) are not added; they go to Plan B's removed list.
- D7 (a): the 2 RemControl hashes are corrected to Group-IB's values and cite the Group-IB post.
- D8: `com.oblivion.dropper` removed.
- D9 (a): secondary-press references (The Hacker News, Security Affairs, Wikipedia) accepted.
- D10 (a): the 6 data-broker homepages are removed and leave the blocking set (297→291).
- D11 (a): EagleMsgSpy ×2 source → `mvt-indicators`; Massistant removed (no browser verification).
- D12: `ads-goal.com` description corrected to an H5 ad-fraud game domain.
- D13 (a): `gecsge4e1e5427f8.com` source → `threatfox`.
- D14 (a): the 2 zhima pipeline-computed SHA-256s removed.
- D15: `craiu/mobiletrackers` accepted as a source; A4 prefixes are per repository.
- Relabel table approved (BTMOB→BtmobRAT ×16, Mirax Bot→Mirax ×1, thd.cc Cerberus→mSpy).
- Section-cited table approved (40 rows; `validation/feed-section-tokens.txt`).

### Round 2 (owner, 2026-10-16)

- D4 revised: the 10 shortened stalkerware names are dropped and nothing is added in their place (the exact ids reach the device through the stalkerware-indicators mirror feed; adding them failed strict complementarity). `com.mspy` removed.
- The 30 unlabelled MalwareBazaar hashes (23 `Unknown`, 7 with the family only in uploader tags) are removed: `feed:malwarebazaar#Unknown` is refused as a generic word and no report exists.
- The 4 removal-table rows without a round-1 ruling are removed: DCHSpy `aa656a24…`, BTMOB `13341c51…`, PromptSpy `net.ustexas.myavlive`, `exovision.cc` (not in the blocking set).

### Controller ruling (2026-10-16)

- The 12 ESET hashes and 13 ESET domains formerly labelled BITTER take family `ProSpy/ToSpy`. The checker does not test a family on an https reference, and ESET publishes the SHA-256s without a family (its per-family table lists SHA-1s; 10 of the 12 SHA-256s are unknown to MalwareBazaar, so no SHA-1 could be obtained), so per-indicator ProSpy vs ToSpy is not checker-confirmable. Existing ESET references kept; `store.latestversion.ai` now cites the welivesecurity post (FOUND) instead of README.adoc.

## Applied

- References from commit bd625b6 (checker FOUND, 540; pdftotext, 1): 541.
- HUMAN BADBOX 2.0 manual references (D1): 76.
- Section citations (approved table): 40, each with a `feed-section-tokens.txt` line; checker SECTION_CITED for all.
- Relabels: BTMOB→BtmobRAT 16, Mirax Bot→Mirax 1, thd.cc→mSpy 1, Triada→Unknown malware 23, Mirax Bot→Unknown malware 4 (source threatfox), BITTER→ProSpy/ToSpy 25. Checker FOUND for every feed relabel.
- Source changes: EagleMsgSpy ×2 → mvt-indicators, gecsge4e1e5427f8.com → threatfox (both FOUND).
- Corrected hashes (D7): `19fef425…a1c9eef…` → `19fef425c3a774e493526126a441a31971db8ac5af84c1d9eef15a272ba02ec1`; `b714f590…b3e980e6…` → `b714f590380e5be8233cd60a4f212d949aff27b3a980e6d644c84b0120dd25b3` (FOUND in the Group-IB post).
- Description fix: `ads-goal.com` (D12).

## Removed entries (58)

*blocked*: was in `validation/blocked-baseline.txt`. *bundle*: present in the AndroDR bundle at 3aea39b (listed for Plan B).

### c2-domains.yml (7)

| indicator | family | source | blocked | bundle | ruling / why |
|---|---|---|---|---|---|
| `adsquare.com` | Adsquare | threat_research | yes | domain_blocklist.txt | D10: data-broker homepage, no report |
| `help.adsquare.com` | Adsquare | threat_research | yes | domain_blocklist.txt | D10: data-broker homepage, no report |
| `explore.venntel.com` | Gravy Analytics | threat_research | yes | domain_blocklist.txt | D10: data-broker homepage, no report |
| `unacast.com` | Gravy Analytics | threat_research | yes | domain_blocklist.txt | D10: data-broker homepage, no report |
| `venntel.com` | Gravy Analytics | threat_research | yes | domain_blocklist.txt | D10: data-broker homepage, no report |
| `mobilewalla.com` | Mobilewalla | threat_research | yes | domain_blocklist.txt | D10: data-broker homepage, no report |
| `exovision.cc` | unknown_rat | threatfox | no | no | round 2: ThreatFox has only a url record (screenshot ref), no report |

### package-names.yml (14)

| indicator | family | source | blocked | bundle | ruling / why |
|---|---|---|---|---|---|
| `com.duiyun` | Cocospy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.minspy` | Cocospy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.sc.cocospy` | Cocospy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.sc.spyic` | Cocospy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.sc.spyzie` | Cocospy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.vvt.android` | FlexiSpy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.meyapico.massistant` | Massistant | threat_research | no | known_bad_packages.json | D11: Lookout 403, no other source names it |
| `com.oblivion.dropper` | Oblivion RAT | threat_research | no | known_bad_packages.json | D8: a class package, not an app id; in no report |
| `net.ustexas.myavlive` | PromptSpy | threat_research | no | known_bad_packages.json | round 2: PromptSpy, in no ESET page or IOC file |
| `com.apspy` | TheTruthSpy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.ttsapp` | TheTruthSpy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.eyezy` | mSpy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |
| `com.mspy` | mSpy | stalkerware-indicators | no | known_bad_packages.json | D4: not in the feed |
| `med.mspy` | mSpy | stalkerware-indicators | no | known_bad_packages.json | D4: shortened name, not in the feed; the exact ids reach the device from the mirror feed |

### malware-hashes.yml (37)

| indicator | family | source | blocked | bundle | ruling / why |
|---|---|---|---|---|---|
| `13341c5171c34d846f6d0859e8c45d8a898eb332da41ab62bcae7519368d2248` | BTMOB | threat_research | no | no | round 2: BTMOB, in no report or IOC file tried |
| `c7944bdac5ce3255a56e77c6f2a83917f4b8a909646396669d408f207e751772` | BTMOB | malwarebazaar | no | no | round 2: MB signature null, family only in uploader tags |
| `018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d01f48` | BeatBanker | malwarebazaar | no | no | round 2: MB signature null, family only in uploader tags |
| `aa656a243d2008327e06fd5bbad919eea99aa271132dbaeabb146e22effbfd1b` | DCHSpy | threat_research | no | no | round 2: DCHSpy, Lookout lists SHA-1 only, in no report |
| `017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44` | Datzbro | malwarebazaar | no | no | round 2: MB signature null, family only in uploader tags |
| `c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14` | Datzbro | malwarebazaar | no | no | round 2: MB signature null, family only in uploader tags |
| `7365190230042fa2f8aba13d39cfecaa52b029750331760bcd114bafb01cb6db` | FakeChrome | malwarebazaar | no | no | round 2: MB signature null, family only in uploader tags |
| `669b75fd2620fa990bb982c07f5233f5b3e98aff65d9d8ffb9683aaae6cb98c1` | NFCShare | malwarebazaar | no | no | D5: MB signature null, tag is only an IP; not in the D3Lab report |
| `62f841f620cea0ce084274878184808bd346da7195edb079a81ceb7fe346bb75` | Oblivion RAT | malwarebazaar | no | no | round 2: MB signature null, family only in uploader tags |
| `fa2a7e4f080ce26715e69732901e80ef2d44f0666fa25c41ee52da9e7c2c4388` | Oblivion RAT | malwarebazaar | no | no | round 2: MB signature null, family only in uploader tags |
| `19fef425c3a774e493526126a441a31971db8ac5af84a1c9eef15a272ba02ec1` | RemControl | threat_research | no | no | D7: transcription error, replaced by the Group-IB value |
| `b714f590380e5be8233cd60a4f212d949aff27b3e980e6d644c84b0120dd25b3` | RemControl | threat_research | no | no | D7: transcription error, replaced by the Group-IB value |
| `05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `1f29ad9ef32cea0d462fd3d74d7bf439757b6de28039ee7c3fcd75b122a03043` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `261305ccbee49fc67c13d275e5788fdc3db8b6a85ec99de16130be93130bcb19` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `bc2a50906c59fdb0e7109274e322d2f8225600b456935d256b45c554975628d1` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `bc877d871e342272ef65e4e8fd3fc5101e7447f51884705037ad67d8821d4ba1` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `fd7c0f6fb3ce15e5e5f713147fd64365e9cdab0d2c23f89aed91005a3ae9e58c` | Unknown | malwarebazaar | no | no | round 2: MB signature null, family Unknown |
| `84d1675640c21bb497bfd230ad31d403d1093a1c75acb2002f84718533b52d08` | zhima | threat_research | no | no | D14: pipeline-computed SHA-256, in no report |
| `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963` | zhima | threat_research | no | no | D14: pipeline-computed SHA-256, in no report |

## Blocking-set change

`validation/blocked-baseline.txt` 297 → 291. Left the blocking set (D10, owner-approved 2026-10-16): `adsquare.com`, `help.adsquare.com`, `mobilewalla.com`, `unacast.com`, `venntel.com`, `explore.venntel.com`. No other removed entry was in the blocking set.

## Not added

- D6 bundle-only hashes: Cerberus `8beae1f6b21cec17eed82fb7af25e1782d5b7bf10fd22369603313f1b1a5e5e4`, SpyNote `17372844a0ecb548c70275a5e06f522a2445f2781410a246130757e0b7bc5396`, Vultur `f4d7e9ec4eda034c29b8d73d479084658858f56e67909c2ffedf9223d7ca9bd2`, AndrMonitor `4b4c1064e3994b59904749fb706c8dfdcc6a50c203694bb45a6d1b4ce11795b3`.
- D4: the feed's exact stalkerware ids (16 checked FOUND) — covered on-device by the mirror feed.
