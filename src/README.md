# Source code

```
src/
├── .env.example        every environment variable (IBM Bob credentials) — copy to backend/.env
├── backend/            FastAPI service
│   ├── main.py         app + routers
│   ├── database.py     SQLite engine, ensure_schema() auto-migration
│   ├── models.py       Asset · IOC · Alert · ThreatEvent · Recommendation
│   ├── schemas.py      Pydantic request / response models
│   ├── seed.py         demo data (8 assets, 11 IOCs, 23 alerts incl. a 5-stage attack chain)
│   ├── routes/         ingest · alerts · brief (+ attack-chains, mitre) · dashboard (+ analyze, ai/status) · assets · iocs
│   ├── services/       feed_ingestor · pipeline · ioc_extractor · threat_intelligence ·
│   │                   correlation_engine · risk_engine · fp_classifier · mitre_mapper · ai_engine (IBM Bob)
│   ├── sample_feeds/   one realistic feed per format: CEF, Suricata syslog, SIEM JSON, EDR CSV, STIX 2.1
│   └── tests/          pytest — parsers, engines, end-to-end API (34 tests)
└── frontend/           React 18 + Vite
    └── src/
        ├── pages/      Dashboard · AlertDetails · CommanderBrief
        ├── components/ FeedIngestPanel · AlertTable · StatsCards · TacticCoverage · VerdictBadge ·
        │               AttackTimeline · RiskBreakdownChart · PriorityBadge · AiEngineBadge
        └── services/   api.js (all backend calls)
```

Run instructions: [../docs/setup-guide.md](../docs/setup-guide.md).
