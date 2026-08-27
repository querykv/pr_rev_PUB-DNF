# Labelled corpus — curation log (labelled)

**Built:** 2026-08-08T01:45:30.148851+00:00 · **advisories examined:** 80 · **accepted:** 26 · **cases pinned:** 52

**Selection criteria, verbatim from the pinned corpus:**

> The 80 most recently published GitHub-reviewed advisories for the pip ecosystem as of 2026-08-07, capped at 2 per source repository and 1 per fixing commit, restricted to those carrying a CWE and a fixing-commit reference into their own repository whose parent is not a merge, whose fix diff is under 400 KB, and which touch reviewable Python source outside tests and docs. Ground-truth spans are the lines the fix removed, excluding spans that are entirely imports, version bumps or comments. Two fixing commits were then excluded by hand as bulk refactors whose spans mark remediation plumbing rather than the defect; the reasons are in benchmark/corpus/labelled-excluded.txt. NOT filtered by CWE: classes no 3a detector can emit are retained and reported as a stratum. Newest-first sampling makes the set post-cutoff for any model evaluated later.

Every advisory the builder examined is listed, accepted or rejected with its reason. A corpus is only as trustworthy as the account of what was left out of it.

## Accepted

| GHSA | CWE | Repo | Fix commit | Ground-truth files |
|---|---|---|---|---|
| `GHSA-fp3f-mc75-235c` | CWE-400 | `py-pdf/pypdf` | `afba8080e19d` | `pypdf/_cmap.py` |
| `GHSA-fwg2-594c-jp42` | CWE-834 | `py-pdf/pypdf` | `51cb6acf9e8a` | `pypdf/_font.py` |
| `GHSA-gm37-52c6-37mw` | CWE-1333 | `facelessuser/pymdown-extensions` | `c68498598d7b` | `pymdownx/betterem.py`, `pymdownx/caret.py`, `pymdownx/magiclink.py`, `pymdownx/tilde.py` |
| `GHSA-wvpp-8hx9-p66j` | CWE-88 | `gitpython-developers/GitPython` | `96a888f4d782` | `git/cmd.py` |
| `GHSA-jm78-9fvv-mhgr` | CWE-74 | `gitpython-developers/GitPython` | `a495ccd3b547` | `git/config.py` |
| `GHSA-6hr6-w5qg-qmwg` | CWE-444 | `python-hyper/h2` | `292a40829fee` | `src/h2/utilities.py` |
| `GHSA-47pj-3jcm-6whg` | CWE-200 | `langchain-ai/langgraph` | `66ebe1a0da92` | `libs/checkpoint-postgres/langgraph/store/postgres/base.py`, `libs/checkpoint-sqlite/langgraph/store/sqlite/aio.py`, `libs/checkpoint-sqlite/langgraph/store/sqlite/base.py` |
| `GHSA-3cg5-48j3-v4gv` | CWE-862 | `open-webui/open-webui` | `915ef7d0798d` | `backend/open_webui/routers/folders.py` |
| `GHSA-2f54-p244-32q6` | CWE-1333 | `open-webui/open-webui` | `3ab2026262ef` | `backend/open_webui/tools/knowledge_fs.py` |
| `GHSA-mfx4-hv73-q22v` | CWE-444 | `aio-libs/aiohttp` | `6ae358f0983c` | `aiohttp/http_parser.py` |
| `GHSA-mq44-7p77-q5h7` | CWE-20 | `aio-libs/aiohttp` | `47fb6ae354d4` | `aiohttp/_websocket/reader_py.py`, `aiohttp/client.py` |
| `GHSA-m8wh-29wm-52mv` | CWE-22 | `keras-team/keras` | `23370f16b0ab` | `keras/src/saving/file_editor.py` |
| `GHSA-c5px-58j2-7fqp` | CWE-22 | `eLyiN/gemini-bridge` | `8f3b85afd02b` | `src/mcp_server.py` |
| `GHSA-cj54-hpcc-gj6h` | CWE-22 | `thumbor/thumbor` | `3b986d13677b` | `thumbor/loaders/file_loader.py` |
| `GHSA-phj3-59pf-cp83` | CWE-400 | `thumbor/thumbor` | `2c716119de98` | `thumbor/filters/proportion.py` |
| `GHSA-22p9-r2f5-22mf` | CWE-59 | `onionshare/onionshare` | `48f31cfac077` | `cli/onionshare_cli/web/send_base_mode.py`, `cli/onionshare_cli/web/share_mode.py` |
| `GHSA-v833-3823-cmhp` | CWE-863 | `onionshare/onionshare` | `a090e97193ef` | `cli/onionshare_cli/web/receive_mode.py` |
| `GHSA-7h3g-4w2f-fj2f` | CWE-668 | `termux/proot-distro` | `98aff324b7d8` | `proot_distro/commands/help/pages.py`, `proot_distro/commands/restore.py` |
| `GHSA-9xq3-3fqg-4vg7` | CWE-61 | `termux/proot-distro` | `a96d7a9667f3` | `proot_distro/commands/restore.py`, `proot_distro/helpers/build_engine/copy_step.py`, `proot_distro/helpers/tar_extract.py` |
| `GHSA-f42x-p2mx-hm8r` | CWE-22 | `brightio/penelope` | `a040afb5db32` | `penelope.py` |
| `GHSA-wjv6-jcfj-mf9r` | CWE-94 | `koxudaxi/datamodel-code-generator` | `b73abb5cd703` | `src/datamodel_code_generator/model/base.py` |
| `GHSA-8359-h9fx-j6v9` | CWE-22 | `koxudaxi/datamodel-code-generator` | `2ff4a72b4550` | `src/datamodel_code_generator/parser/jsonschema.py` |
| `GHSA-3fcr-jvgp-7f58` | CWE-287 | `nessshon/tonapi` | `854222b7ee68` | `pytonapi/webhook/dispatcher.py` |
| `GHSA-j6g5-3hh3-pgw8` | CWE-88 | `aws/bedrock-agentcore-sdk-python` | `3c4b4ee6b873` | `src/bedrock_agentcore/tools/code_interpreter_client.py` |
| `GHSA-hmj8-5xmh-5573` | CWE-400 | `libp2p/py-libp2p` | `146ea87d1a20` | `libp2p/stream_muxer/yamux/yamux.py` |
| `GHSA-29w2-fq35-v728` | CWE-455 | `awslabs/mcp` | `ab1bbebc097d` | `src/aws-api-mcp-server/awslabs/aws_api_mcp_server/server.py` |

## Rejected

| GHSA | Repo | Reason |
|---|---|---|
| `GHSA-hmq2-w58f-27jc` | `gitpython-developers/GitPython` | per-repo cap (2) already reached for gitpython-developers/GitPython |
| `GHSA-hh9p-6wh2-4mfc` | `gitpython-developers/GitPython` | per-repo cap (2) already reached for gitpython-developers/GitPython |
| `GHSA-9rj7-rf2p-w77r` | `gitpython-developers/GitPython` | per-repo cap (2) already reached for gitpython-developers/GitPython |
| `GHSA-4gmw-gg2m-w46p` | `gitpython-developers/GitPython` | per-repo cap (2) already reached for gitpython-developers/GitPython |
| `GHSA-hqvf-45jj-mccq` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-pwxh-7358-jq2x` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-3r7g-q6cg-q2vx` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-5gpj-vj23-vhhv` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-73cq-mcgh-379c` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-h6x2-583h-x99r` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-6xhv-rxhv-pwm4` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-jxc9-xmc4-gr23` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-3xpf-xq7r-v8c5` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-8x5v-cpv7-8jjp` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-g423-grf7-98rv` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-rffm-9q57-q649` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-3vf6-64vr-3g56` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-rq84-p6rr-vf89` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-mj5r-jf49-m3w7` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-w2rx-84hp-gg95` | `open-webui/open-webui` | per-repo cap (2) already reached for open-webui/open-webui |
| `GHSA-m2h6-j472-rp4c` | `pyca/cryptography` | fix touches no reviewable Python source outside tests/docs |
| `GHSA-jwv3-5hgf-82ww` | `pyca/cryptography` | fix touches no reviewable Python source outside tests/docs |
| `GHSA-g6cj-pr64-35w5` | `pyca/cryptography` | fix touches no reviewable Python source outside tests/docs |
| `GHSA-cq5v-8q36-5273` | `aio-libs/aiohttp` | fix touches no reviewable Python source outside tests/docs |
| `GHSA-p538-c434-8v24` | `gitpython-developers/GitPython` | per-repo cap (2) already reached for gitpython-developers/GitPython |
| `GHSA-539m-9xh6-q6rr` | `gitpython-developers/GitPython` | per-repo cap (2) already reached for gitpython-developers/GitPython |
| `GHSA-3f7w-8rr8-f37f` | `gitpython-developers/GitPython` | per-repo cap (2) already reached for gitpython-developers/GitPython |
| `GHSA-5vjc-7cxw-4w6j` | `thumbor/thumbor` | per-repo cap (2) already reached for thumbor/thumbor |
| `GHSA-cqjp-jf4r-h5q9` | `thumbor/thumbor` | per-repo cap (2) already reached for thumbor/thumbor |
| `GHSA-mw3h-qjxj-6xg9` | `thumbor/thumbor` | per-repo cap (2) already reached for thumbor/thumbor |
| `GHSA-6x26-6r6f-m537` | `thumbor/thumbor` | per-repo cap (2) already reached for thumbor/thumbor |
| `GHSA-qvv7-cg9c-w4x3` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-fg7f-2386-8897` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-6hm5-jgcp-p838` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-xh95-f55m-82fw` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-c9hr-64h3-gxpc` | `flytohub/flyto-core` | excluded by hand: bulk refactor across 16 modules; spans mark plumbing, not the defect |
| `GHSA-pgwh-4jj4-qm8v` | `flytohub/flyto-core` | excluded by hand: bulk refactor across 16 modules; spans mark plumbing, not the defect |
| `GHSA-jx74-cqjv-2c67` | `flytohub/flyto-core` | excluded by hand: bulk refactor across 16 modules; spans mark plumbing, not the defect |
| `GHSA-qq9q-xgm3-xv9g` | `flytohub/flyto-core` | excluded by hand: bulk refactor across 18 modules; spans mark plumbing, not the defect |
| `GHSA-hr7p-wg7r-hg9m` | `flytohub/flyto-core` | excluded by hand: bulk refactor across 18 modules; spans mark plumbing, not the defect |
| `GHSA-2956-977x-2w3r` | `flytohub/flyto-core` | excluded by hand: bulk refactor across 18 modules; spans mark plumbing, not the defect |
| `GHSA-4jc5-g844-4x33` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-wchh-9x6h-7f6p` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-386q-5hp3-95m9` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-vx7x-vcc2-c44g` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-8m8r-38jm-f355` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-954p-556p-r752` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-5578-w22f-pfx9` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-j884-q54q-mmx3` | `—` | no fixing-commit reference into the advisory's own repo |
| `GHSA-m34r-v34r-rf9q` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-r5vv-ff45-prp2` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-rfr2-mq9m-x2qx` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-442q-2j6p-642g` | `koxudaxi/datamodel-code-generator` | per-repo cap (2) already reached for koxudaxi/datamodel-code-generator |
| `GHSA-85rg-p3fr-xc2f` | `—` | no fixing-commit reference into the advisory's own repo |

## Hand verification

The spans above are **candidates**, derived from the lines the fix removed. Each accepted case still needs a human to confirm that the advisory's CWE is what the diff actually fixes, that the fix commit is the whole fix rather than one of several, and that the spans cover the vulnerable lines and nothing else. Record the outcome here, including cases dropped on inspection.
