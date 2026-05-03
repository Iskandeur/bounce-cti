# PIVOT_MAPPING.md — Architecture du moteur d'autonomie

**Statut** : proposition pour review avant code.
**Branche** : `feat/autonomy-engine`
**Remplace** : workflow STEP 1→8 monolithique de `agent_runner.py:220-800` + Phase 2/3 fallback.

---

## 0. TL;DR — ce qui change

| Avant | Après |
|---|---|
| Workflow procédural figé dans le system prompt (STEP 1→8 par seed type) | Machine à états : `SEED_BOOTSTRAP → DRAIN_QUEUE → EXHAUSTION_CHECK → CONVERGE_OR_LOOP → SELF_CRITIQUE → REPORT` |
| Pas de queue : l'agent décide ce qu'il fait au prochain tour | Queue first-class en SQLite : chaque `add_node`/`add_edge` enqueue automatiquement les pivots applicables au type |
| Hard-cap 80 tool calls (R4) | Soft-cap 60 (cible PURPOSE/EVAL), extension justifiée par yield (≥1 fingerprint discriminant / 5 derniers calls), hard-cap 90 |
| Critère d'arrêt subjectif (« je pense avoir fini ») | Provable : 2 passes consécutives de `DRAIN_QUEUE` sans nouveau **fingerprint discriminant** |
| Phase 2 = patch correctif (re-injecte tools manquants) | Phase 2 conservée comme **filet de sécurité** pendant 1-2 semaines de validation, puis suppression. La state machine est prioritaire ; Phase 2 se déclenche uniquement si la state machine n'a pas convergé proprement |
| Phase 3 = fallback écriture rapport | Phase 3 conservée comme filet pareil. Suppression différée |
| 1 clé par source (`VT_KEY`) | Pool de clés rotatif (`VT_KEY` ou `VT_KEYS=k1,k2,k3`), cooldown sur 429, tracking quota journalier |

---

## 1. Schéma SQLite — nouvelle table `pivot_tasks`

```sql
CREATE TABLE pivot_tasks (
    id              TEXT PRIMARY KEY,           -- SHA1(inv_id|node_type|node_value|pivot_op)[:16]
    investigation_id TEXT NOT NULL,
    node_type       TEXT NOT NULL,              -- domain, ip, hash, url, jarm, asn, cert_serial, email, favicon_hash, ...
    node_value      TEXT NOT NULL,
    pivot_op        TEXT NOT NULL,              -- nom du tool MCP à appeler (ex: "virustotal_domain")
    priority        INTEGER NOT NULL DEFAULT 5, -- 1=high, 9=low. seed pivots = 1, dérivés = 5, exotiques = 7
    status          TEXT NOT NULL DEFAULT 'pending',
                                                -- pending | running | done | skipped | failed
    skip_reason     TEXT,                       -- 'no_api_key', 'tier_locked', 'rate_limit', 'cdn_node', 'duplicate', ...
    result_summary  TEXT,                       -- ce que l'agent a appris (court, < 200 chars)
    attempts        INTEGER NOT NULL DEFAULT 0,
    enqueued_at     INTEGER NOT NULL,           -- epoch
    started_at      INTEGER,
    completed_at    INTEGER,
    UNIQUE(investigation_id, node_type, node_value, pivot_op)
);
CREATE INDEX idx_pivot_tasks_inv_status ON pivot_tasks(investigation_id, status);
CREATE INDEX idx_pivot_tasks_inv_priority ON pivot_tasks(investigation_id, priority, enqueued_at);
```

**Idempotence** : la clé unique `(inv, type, value, op)` garantit qu'on ne re-enqueue jamais le même pivot deux fois. Si le mapping pousse `(domain:evil.com, virustotal_domain)` 3 fois, seule la première insertion réussit, les suivantes sont silently no-op.

---

## 2. Mapping pivots — par type de nœud

Auto-déclenché côté `graph_mcp.add_node()` (et `add_edge()` pour les types qui n'apparaissent qu'en relation, comme `email` du registrant ou `ns` du domaine).

| Type de nœud | Pivots déclenchés | Priorité | Notes |
|---|---|---|---|
| **`domain`** | `rdap_domain`, `dns_resolve_a`, `dns_resolve_aaaa`, `dns_resolve_mx`, `dns_resolve_ns`, `dns_resolve_txt`, `crtsh_subdomains`, `virustotal_domain`, `virustotal_subdomains`, `virustotal_domain_resolutions`, `urlscan_search_domain`, `wayback`, `otx_domain`, `onyphe_domain`, `threatfox_search`, `urlhaus_host`, `mnemonic_pdns`, `certspotter_issuances` *(new)* | 1 (seed) / 3 (dérivé) | dns_resolve_* éclatés en 5 ops pour pouvoir tracker ce qui a été fait |
| **`ip`** | `rdap_ip`, `reverse_dns`, `virustotal_ip`, `virustotal_ip_resolutions`, `virustotal_communicating_files`, `shodan_host`, `onyphe_ip`, `otx_ip`, `ip_api_lookup`, `mnemonic_pdns_ip`, `threatfox_search`, `urlhaus_host`, `abuseipdb_check` *(new)*, `criminalip_ip` *(new)* | 1 (seed) / 3 (dérivé) | si `defuse(ip)` retourne `should_stop_pivot`, **tous les pivots sont skip avec `skip_reason='cdn_node'`** sauf `rdap_ip` |
| **`hash`** (file) | `virustotal_file`, `otx_file`, `malwarebazaar_hash` | 1 (seed) / 3 (dérivé) | |
| **`url`** | `urlscan_search_url`, `wayback`, `virustotal_url`, `dom_fingerprints` *(new, Phase 2)* | 3 | dom_fingerprints parse le résultat urlscan déjà récupéré, pas de nouvelle API |
| **`jarm`** | `onyphe_datascan_jarm`, `shodan_search_jarm`, `netlas_jarm` *(new)*, `zoomeye_jarm` *(new)* | 2 | très discriminant, priorité haute |
| **`asn`** | `onyphe_datascan_asn`, `shodan_search_asn`, `netlas_search_asn` *(new)* | 5 | si ASN cloud (AS14618 AWS, AS16509 AWS, AS15169 Google, AS13335 Cloudflare…) → skip avec `skip_reason='cdn_asn'` |
| **`cert_serial`** | `crtsh_serial`, `certspotter_serial` *(new)* | 4 | |
| **`email`** (registrant ou contact) | `whoxy_reverse` *(new)* | 4 | reverse WHOIS — gros levier de pivot |
| **`ns`** (nameserver) | `crtsh_subdomains` (sur le NS lui-même), tag CDN/dyndns via `defuse(ns)` | 6 | utile seulement si NS non-CDN |
| **`favicon_hash`** *(new, Phase 2)* | `shodan_search_favicon`, `netlas_favicon` *(new)*, `zoomeye_favicon` *(new)* | 2 | mmh3 hash, format compatible Shodan |
| **`title_hash`** *(new, Phase 2)* | aucun pivot direct | — | sert de connecteur entre nœuds (deux pages avec même title hash → edge automatique) |
| **`tracking_id`** *(new, Phase 2)* | `urlscan_search_tracking` *(new)*, `criminalip_tracking` *(new si supporté)* | 2 | GA/GTM/FB/Yandex/Hotjar |
| **`form_action`** *(new, Phase 2)* | enqueue le domaine extrait de l'URL d'action comme nouveau nœud `domain` | 4 | typique des kits phishing qui pointent leur backend ailleurs |
| **`wallet_address`** *(new, Phase 2)* | aucun pivot direct (v1) | — | logué pour le rapport, pivot blockchain hors scope v1 |
| **`js_hash`** *(new, Phase 2)* | aucun pivot direct (v1) | — | logué, recherche réservée v2 |

**Règles de gating** appliquées avant `enqueue` :
1. Si `defuse(node)` retourne `should_stop_pivot=True` → seuls les pivots de "documentation" (rdap, dns_resolve_*) sont enqueued, le reste est inséré direct en `status='skipped', skip_reason='defused'`. Permet de tracer dans `coverage_matrix` qu'on a *vu* le nœud sans avoir gâché de quota.
2. Si la clé API est manquante → pivot inséré en `status='skipped', skip_reason='no_api_key'`. Visible dans `gaps_report`.
3. Si le pivot a déjà été tenté pour ce nœud (UNIQUE constraint) → no-op silencieux.
4. **Fan-out par nœud parent** : max 8 pivots priority ≤ 3 + max 4 pivots priority ≥ 4 par nœud. Au-delà → `skip_reason='fanout_per_node'`.
5. **Fan-out par hop** : max 30 nouveaux nœuds `domain` ou `ip` par hop (compteur reset à chaque transition `DRAIN_QUEUE`). Au-delà → `skip_reason='fanout_per_hop'`. Crucial pour les cas type Smishing Triad (Case 11 EVAL : ~25 000 domaines vivants en 8 jours).

---

## 3. Machine à états — exécution

```
                ┌─────────────────┐
                │ SEED_BOOTSTRAP  │   enqueue les pivots du seed
                └────────┬────────┘
                         ▼
                ┌─────────────────┐ ◄────┐
       ┌────────│  DRAIN_QUEUE    │      │
       │        └────────┬────────┘      │
       │                 ▼               │
       │        ┌─────────────────┐      │
       │        │EXHAUSTION_CHECK │      │ requeue trous
       │        └────────┬────────┘      │
       │                 ▼               │
       │        ┌─────────────────┐      │
       └───────▶│CONVERGE_OR_LOOP │──────┘
            no  └────────┬────────┘
                yes (2 passes vides) │
                         ▼
                ┌─────────────────┐
                │  SELF_CRITIQUE  │   gaps_report
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │     REPORT      │   add_node(report, ...)
                └─────────────────┘
```

### États en détail

**SEED_BOOTSTRAP** (1 entrée par investigation)
- L'agent appelle `add_node(seed_type, seed_value)` → l'auto-enqueue déclenche les pivots du seed type
- Transition automatique vers `DRAIN_QUEUE`

**DRAIN_QUEUE** (état actif, le plus long)
- L'agent appelle `next_pivot()` qui retourne `{task_id, node_type, node_value, pivot_op}` (priorité décroissante puis FIFO)
- L'agent appelle le `pivot_op` correspondant (ex: `virustotal_domain("evil.com")`)
- L'agent appelle `mark_pivot_done(task_id, summary)` avec un résumé court
- Les nouveaux nœuds créés par le pivot auto-enqueuent leurs propres pivots
- Quand `next_pivot()` retourne `null` (queue vide) → transition vers `EXHAUSTION_CHECK`

**EXHAUSTION_CHECK** (gardien d'invariant)
- L'agent appelle `coverage_matrix()` qui retourne, pour chaque nœud, `{pivots_done, pivots_pending, pivots_skipped, pivots_missing}`
- Si `pivots_missing` non vide pour un nœud → `requeue_missing()` → retour `DRAIN_QUEUE`
- Sinon → `CONVERGE_OR_LOOP`

**CONVERGE_OR_LOOP** (critère d'arrêt provable)
- Compteur `consecutive_empty_drains` géré par le runner Python (pas par l'agent)
- Un drain est "vide" si pendant l'état `DRAIN_QUEUE` qui vient de se terminer, **0 nouveau fingerprint discriminant** a été ajouté au graphe
- Si `consecutive_empty_drains >= 2` → `SELF_CRITIQUE`
- Sinon → retour `DRAIN_QUEUE` (la matrice de couverture a peut-être requeue des trous)

**SELF_CRITIQUE** (1 entrée)
- L'agent appelle `gaps_report()` → liste des pivots `skipped`/`failed` avec raisons groupées (`{no_api_key: [whoxy_reverse, netlas_jarm], rate_limit: [virustotal_domain x3], cdn_asn: [shodan_search_asn]}`)
- L'agent doit intégrer cette section dans le rapport final (vérifié structurellement : le rapport doit contenir un champ `gaps`)
- Transition vers `REPORT`

**REPORT** (1 entrée, terminal)
- L'agent appelle `add_node(type='report', value='investigation_summary', metadata={...})`
- Le runner Python vérifie que le rapport est bien là et termine

---

## 4. Convergence — qu'est-ce qu'un "fingerprint discriminant" ?

Un nœud ajouté pendant un cycle `DRAIN_QUEUE` compte comme **discriminant** ssi :

**Type ∈** `{jarm, favicon_hash, cert_serial, tracking_id, wallet_address, email}`
**OU** type `ip` ET pas tagué `cdn`/`parking`/`sinkhole`/`dyndns`
**OU** type `asn` ET pas dans la liste cloud (`AS14618`, `AS16509`, `AS15169`, `AS13335`, `AS8075`, `AS32934`, `AS16276`, `AS14061`, `AS20473`, `AS24940`, `AS396982`)
**OU** type `domain` ET pas tagué `cdn`/`parking`/`sinkhole`/`dyndns` ET pas un sous-domaine d'un domaine déjà marqué CDN
**OU** type `ns` ET pas tagué `cdn`/`dyndns`

Un nœud ne compte **pas** comme discriminant si :
- Tagué CDN, parking, sinkhole, dyndns par `defuse_lists`
- Type ∈ `{title_hash, form_action, js_hash}` (utiles comme connecteurs mais pas discriminants seuls)
- Type `report` (méta)
- Déjà présent dans le graphe avant ce cycle

**Implémentation** : le runner snapshotte `nodes.id` set au début de `DRAIN_QUEUE`, compare au set à la fin, filtre par les règles ci-dessus. Si delta ≠ ∅ → drain "fertile", reset `consecutive_empty_drains` à 0. Sinon → `consecutive_empty_drains += 1`.

---

## 5. Nouveaux MCP tools — `graph_mcp.py`

| Tool | Signature | Retour | Usage |
|---|---|---|---|
| `next_pivot` | `()` | `{task_id, node_type, node_value, pivot_op} \| null` | Pop la prochaine tâche (priorité ↑, FIFO) et la marque `running` |
| `mark_pivot_done` | `(task_id: str, summary: str, status: 'done'\|'failed'='done')` | `{ok: bool}` | Ferme la tâche, log un event |
| `queue_status` | `()` | `{pending: int, running: int, done: int, skipped: int, failed: int, by_op: {...}}` | Vue d'ensemble pour décision agent |
| `coverage_matrix` | `()` | `{nodes: [{id, type, value, pivots_done: [...], pivots_pending: [...], pivots_skipped: [...], pivots_missing: [...]}]}` | Détecte les trous, requeue par `requeue_missing` |
| `requeue_missing` | `()` | `{enqueued: int}` | Réinjecte les pivots `missing` (jamais tentés) en `pending` |
| `gaps_report` | `()` | `{by_reason: {no_api_key: [...], rate_limit: [...], cdn_node: [...], ...}, total_skipped: int, total_failed: int}` | Pour la section "Limitations" du rapport |
| `quota_status` | `()` | `{by_source: {vt: {used, remaining, keys_in_pool}, ...}}` | L'agent peut réorienter vers d'autres sources si quota épuisé |
| `fingerprint_extract` | `(urlscan_uuid: str)` | `{favicon_hash, title_hash, tracking_ids, form_actions, wallet_addresses, js_hashes}` | Phase 2 — appelé en pivot auto sur les `url` ou en explicite par l'agent |

Tools existants conservés : `add_node`, `add_edge`, `tag_node`, `get_graph`, `get_node`, `get_report`, `defuse`.

---

## 6. Pool de clés — `backend/key_pool.py`

```python
# .env nouveau format (rétro-compatible) :
VT_KEY=xxx              # ancien format conservé (alias de VT_KEYS=xxx)
VT_KEYS=k1,k2,k3        # nouveau format multi-clés

# Mêmes deux formats pour : URLSCAN, ONYPHE, SHODAN, OTX, ABUSECH,
#                          ABUSEIPDB, CERTSPOTTER, NETLAS, WHOXY,
#                          ZOOMEYE, CRIMINALIP
```

**API publique** :
```python
key = key_pool.next("vt")               # round-robin, retourne None si toutes en cooldown
key_pool.mark_rate_limited("vt", key, cooldown_seconds=60)
key_pool.mark_quota_exhausted("vt", key, until=epoch_tomorrow_midnight_utc)
key_pool.status("vt") -> {keys_total, keys_available, keys_cooldown, used_today_per_key}
```

**Persistence** : compteurs journaliers stockés dans la table `cache` existante avec clé `quota:vt:k1:2026-05-03 = {used: 47, last_429_at: ...}`. Reset auto à minuit UTC.

**Heuristique 429** : si une clé reçoit 429, cooldown 60s. Si elle reçoit 3× 429 en 5 min, cooldown 1h. Si toutes les clés sont en cooldown, la source retourne `{"error": "all keys exhausted, retry later"}`.

---

## 7. Soft-cap budget — remplacement de R4

**Avant (`agent_runner.py:231`)** :
```
R4. Budget: max 80 tool calls total. Stop adding nodes once budget exhausted.
```

**Après** :
```
R4. Budget intelligent (yield-based) :
    - Soft-cap 60 tool calls (cible PURPOSE / scoring EVAL §4.5).
    - Extension autorisée (jusqu'à 90 hard-cap) ssi les 5 derniers tool calls
      ont produit ≥ 1 fingerprint discriminant. Sinon → SELF_CRITIQUE + REPORT.
    - Si extension activée, le runner log un event `budget_extension` avec
      le yield observé (ex: "extending: last 5 calls yielded 2 new JARMs").
    - Hard-cap absolu 90. À 90 → SELF_CRITIQUE forcé puis REPORT.
    - Sortie propre garantie : si l'agent crashe avant REPORT, le runner
      écrit un rapport tronqué avec metadata={truncated: true}.
```

**Pourquoi 90 et pas 120 ou 60** :
- 60 est la cible PURPOSE et le seuil EVAL §4.5 pour BD=100. C'est le standard du tool comme triage rapide.
- 90 est le seuil EVAL §4.5 où BD bascule à 0. Au-delà, on dégrade structurellement le score d'éval.
- Doubler à 120 cassait le positionnement « fast-triage ». L'extension yield-based laisse de la marge sur les cas riches **sans pénaliser systématiquement**.

**Côté runner** : compteur du nombre de tool calls, hook sur dépassement 60 (commence à vérifier le yield à chaque call), 90 (kill switch + SELF_CRITIQUE forcé).

**Note EVAL** : `EVAL_PROTOCOL_V2.md` §4.5 reste valide (BD pénalise > 60). Le tool n'aura un BD < 100 sur un cas que s'il a réellement besoin d'étendre — et le `gaps_report` justifie l'extension. C'est un trade-off conscient : -50 sur BD vs +30 sur NR/ER pour les cas complexes (Case 1, 9, 11). Globalement net positif.

---

## 8. Suppression Phase 2 / Phase 3 actuelles — DIFFÉRÉE

Avec la state machine, ces phases deviennent **redondantes** mais leur suppression est différée pour éviter de casser la production :

**Stratégie dual-run (1-2 semaines)** :
- La state machine est **prioritaire** : si elle converge proprement (REPORT atteint dans le budget), Phase 2/3 sont skip.
- Phase 2 ne se déclenche que si :
  (a) l'agent a crashé avant REPORT, OU
  (b) `coverage_matrix` à la fin de Phase 1 montre encore des `pivots_missing` non-defused.
- Phase 3 (fallback rapport) ne se déclenche que si toujours pas de report node après Phase 1 + 2.
- Chaque déclenchement de Phase 2/3 est loggé comme `safety_net_triggered` pour qu'on puisse mesurer leur utilité.

**Critère de suppression définitive** : si Phase 2 ne se déclenche pas pendant 50 investigations consécutives (mesurable via les events), on supprime. Visible dans la table `events` filtrée par `kind='safety_net_triggered'`.

Code à conserver mais isoler dans `agent_runner.py` :
- Lignes ~1240–1326 (Phase 2 logic + `_FOLLOWUP_SYSTEM_PROMPT`) — on garde mais on conditionne le déclenchement.
- Lignes ~1350–1455 (Phase 3 fallback) — pareil.
- Mapping `mandatory_tools` lignes ~82–136 — devient redondant avec la matrice de couverture, mais conservé en backup.

---

## 9. Invariants & garanties

1. **Idempotence** : un pivot ne peut être enqueued qu'une fois par nœud.
2. **Terminaison provable** : 2 drains consécutifs sans nouveau fingerprint discriminant + matrice complète = condition nécessaire et suffisante.
3. **Auditabilité** : chaque pivot a un `task_id` et un event lifecycle (`enqueued → started → done|skipped|failed`).
4. **Lucidité forcée** : aucun rapport sans `gaps_report` intégré.
5. **Rétro-compatibilité clés** : `VT_KEY=xxx` continue de marcher.
6. **Degradation gracieuse** : pas de clé = pivot skipped explicitement, pas un crash.

---

## 10. Points ouverts à valider avec toi

1. **Granularité `dns_resolve_*`** : j'ai éclaté en 5 ops (a/aaaa/mx/ns/txt) pour la traçabilité. OK ou trop verbeux ?
2. **Cloud ASN list** : la liste codée en dur (AS14618, AS16509, etc.) — tu veux que je l'externalise dans `defuse_lists.py` pour pouvoir l'éditer sans toucher au code ?
3. **`fingerprint_extract`** : auto-pivot sur tous les nœuds `url`, ou seulement sur les `url` venant de urlscan (pour éviter de re-fetcher) ? Ma reco : seulement urlscan, on a déjà la donnée.
4. **Convergence à 2 passes** : si la 1ère passe est vide mais la matrice détecte des trous (donc requeue), est-ce que la 2ème passe compte comme "consécutive vide" ? Ma reco : **non**, le requeue reset le compteur (sinon on peut sortir avec des trous non explorés).
5. **`requeue_missing`** : auto-déclenché par `EXHAUSTION_CHECK`, ou geste explicite de l'agent ? Ma reco : **auto** — sinon l'agent peut "oublier" et la garantie d'épuisement saute.
6. **Self-critique structurée** : je propose que `gaps_report()` retourne du JSON et que l'agent le formate en prose dans le rapport. Alternative : le tool retourne directement du Markdown prêt à coller. Ma reco : JSON + prose libre, pour garder l'agent dans une posture analytique.
7. **Migration des investigations en cours** : à l'instant du déploiement, il peut y avoir des investigations actives. Ma reco : on laisse les investigations en cours finir avec l'ancien runner (snapshot `agent_runner_legacy.py`), nouvelles investigations utilisent le nouveau. Schéma SQLite : `pivot_tasks` est nouvelle table, pas de break.
8. **Versioning du prompt** : on tag le system prompt avec une version (`v2.0-state-machine`) loggée dans events au démarrage de chaque investigation, utile pour comparer les runs.

---

## 11. Plan d'exécution (rappel)

Une fois ce doc validé, l'ordre des commits sera :

1. `feat: add pivot_tasks table + migrations`
2. `feat: add key_pool with rotation + cooldown`
3. `feat: auto-enqueue pivots on add_node/add_edge`
4. `feat: add MCP tools next_pivot, mark_pivot_done, queue_status`
5. `feat: add MCP tools coverage_matrix, requeue_missing, gaps_report, quota_status`
6. `feat: rewrite system prompt as state machine`
7. `feat: convergence + soft-cap budget logic in agent_runner`
8. `refactor: remove obsolete Phase 2/3 fallbacks`
9. (test local sur seed de référence — pas de commit)
10. `feat: DOM fingerprint extractor (Phase 2)`
11. `feat: add source <name>` × N (Phase 3)
12. `docs: update CLAUDE.md, ARCHITECTURE.md, README.md, .env.example`
13. (re-run EVAL_PROTOCOL_V2 — pas de commit)
14. `merge feat/autonomy-engine → main`

Chaque commit est testable indépendamment. Reverter un commit ne casse pas les précédents.
