# TD-46 cluster — impact analysis на текущий момент (2026-04-22)

Создан по директиве user'а 2026-04-22: "D (upstream) Надо проверить, возможно
этот фикс уже сделан в свежих релизах! Если нет, то откладываем в бэклог
(все равно сделают они этот фикс очень не скоро) и делаем анализ — чем нам
это грозит на данном этапе."

## Upstream проверка — нет фикса

- libp2p 0.57.0 / relay 0.22.0 / swarm 0.48.0 — unreleased на crates.io,
  только staged в master.
- Byte-level диф master vs shipped 0.21.1 на crash site
  (`priv_client::Behaviour::handle_established_outbound_connection`,
  `MultiaddrExt::is_relayed`, `priv_client/transport.rs`): **identical**
  modulo rustfmt import-order shuffle.
- Единственное функциональное изменение в 0.22.0 — `Behaviour::set_status`
  для relay server HOP advertisement, не client-side.
- Заключение: **upstream НЕ закрыл баг.** Даже когда 0.57.0 выйдет,
  relay-client крэши останутся.

## Что нам грозит сейчас (v0.0.7)

### Прямой риск — НУЛЕВОЙ

TD-51 (NIM-93) **физически удалил** relay-client из композита. Не toggle'нут
(`Toggle::from(None)` с Handler tower'ом остающимся), а вообще не построен:
- `relay::client::new(local_peer_id)` не вызывается.
- `relay::client::Behaviour` не конструируется.
- Relay transport половина не композируется в swarm transport.
- `priv_client::handler::Handler` отсутствует в handler tower любого
  Connection.

Следовательно, все три известных libp2p-relay крэша (TD-46 NULL-deref в
is_relayed, TD-48 panic при listen_on(/p2p-circuit), TD-50 SIGBUS в
priv_client::handler drop) **физически недостижимы** на ship-gate9+ libcabi.

### Продуктовый риск — ограниченная reachability

Без relay-client пропадает NAT-traversal через circuit relay. Это значит:
- **Прямые диалы работают**: peer'ы с публичным IPv4, в одной LAN, или
  peer'ы с IPv6. DHT lookup работает. Gossipsub работает (registry + чаты
  идут через bootstrap relay node'ы, те остаются).
- **Не работают**: peer'ы за симметричным NAT. Это **большая часть мобильных
  пользователей** на cellular (большинство операторов ставят CGNAT). Также
  hotel/corp Wi-Fi с strict NAT. VPN-юзеры — смешанно, зависит от провайдера.

**Для v0.0.7 MVP продуктово приемлемо**, потому что:
1. Нет продуктивных пользователей — можно тестировать на LAN / public-IP
   парах.
2. Ship-gate9 только что подтвердил direct-only работает чисто (при
   отсутствии relay-client крэшей).
3. TD-52 (NIM-94) priority-elevated в v0.0.8 возвращает relay-client через
   локальный форк + upstream PR.

### Скрытые риски

1. **Fork libp2p-relay (TD-52) окажется сложнее ожидаемого.**
   Если diagnostic работа на debug libcabi не локализует UAF с первого
   захода, v0.0.8 может дрейфить на недели. Митигация: time-box TD-52
   triage в 2 недели; если не локализовано — эскалация к system-architect
   на refactor composition или ждём upstream.
2. **Upstream сам поправит раньше, чем мы подадим PR.** Низкая вероятность
   (upstream исторически медленный на такие issues + никто кроме нас пока
   не репродуцировал это публично). Если случится — мы просто мигрируем с
   форка на crates.io release, плюсом останется наш добавленный
   reproduction test.
3. **Пользователи v0.0.7 MVP жалуются на "не могу никого дозваться".** Это
   ожидаемое поведение без relay, но users могут принять за bug. Митигация:
   честное release-note с указанием "direct-only MVP, full reachability in
   v0.0.8".

## Что мы записали в бэклог

- **NIM-94 (TD-52)** — priority-elevated. Fork + instrument + upstream PR +
  `[patch.crates-io]` на v0.0.8 до merge'а upstream.
- **Upstream issue draft** — сохранён в
  `fidonext-core/c-abi-libp2p/docs/upstream-issue-draft-2026-04-22.md` с
  полным описанием трёх bug'ов и всеми backtrace'ами. Готов к отправке как
  только TD-52 работа начнётся (обычно upstream ожидает воспроизводимый
  case + попытку локального патча параллельно с issue).

## Что НЕ делаем

- **Не файлим upstream issue сейчас.** Причина (user'а): "все равно сделают
  они этот фикс очень не скоро". Отправка без попытки локального фикса +
  без reproduction test даст нам низкоприоритетный issue, который полежит в
  триаже.
- **Не пинним libp2p 0.57.0** — её нет на crates.io. Когда появится —
  оценим отдельно, но Ход 2B показал что это не помогает.
- **Не пишем defensive guard в `is_relayed`** — функция тривиально
  безопасна; crash это UAF через safe Rust, guard'ом не спрятать.

## Exit criteria для переоценки

Пересматриваем ситуацию когда:
1. TD-52 fork + defensive guard merge'нутся локально + ship-gate10 с
   rel-client включённым пройдёт на amnezia+kunzite, ИЛИ
2. libp2p 0.57.0 релизнется и включает фикс relay-client UAF
   (маловероятно), ИЛИ
3. Получаем production bug report на v0.0.7 который связан с direct-only
   деградацией и не решается через relay node'ы (в which case может
   ускорить TD-52 priority или переосмыслить релиз-стратегию).

Пока — v0.0.7 ship-ready с TD-53 + ship-gate10 финальной валидацией.
