---
'@hyperdx/api': patch
---

fix: Look teams up by ID. `getTeam` ignored its ID and returned the first team in the database, so on an instance with more than one team, members of other teams were shown the first team's settings and ingestion API key.
