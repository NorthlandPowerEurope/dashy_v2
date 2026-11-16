# Dashy cleanup and authentication audit changes

- Removed Go test files, testdata, Git metadata/sample hooks, and example OPC UA client/server commands and their test certificates/keys.
- Preserved OPC UA library packages and operational certificates/keys in agent directories.
- Added structured LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, SESSION_EXPIRED, SESSION_INACTIVE and INVALID_SESSION events to the existing servicekit logger.
- Audit timestamps are UTC. `audit_id` is a non-secret random identifier, not the session cookie.
- Heartbeat POST /heartbeat every 30 seconds from dashboard, index and history pages, compatible with older XMLHttpRequest browsers. Missing heartbeats for 90 seconds are logged as inactivity, NOT automatic logout. Heartbeat is only evidence of a page's activity, not definitive browser closure.
- Existing session timeout remains unchanged. Expiration events are emitted during periodic cleanup.
- IP is the direct TCP peer address; reverse-proxy headers are deliberately not trusted.
- No OPC UA certificate verification settings were changed.

## Deployment notes

- Test on a staging instance first. Go compiler was not available in the modification environment, so compilation and automated tests were not executed.
- Because this is a source-only ZIP, restore production secrets/configuration separately; do not publish private keys from the source tree.
- Existing authentication security weaknesses identified in the initial review are not remediated by this scoped change.
- `SESSION_INACTIVE` is not proof that the browser was closed: network loss, suspended tab, or PC shutdown can cause it.
- A heartbeat request may extend the existing sliding session timeout while a dashboard page remains open.
