import sys, traceback
sys.path.insert(0, '.')
from database import get_db, ensure_schema
ensure_schema()
db = next(get_db())

from services import feed_ingestor, pipeline
from routes.ingest import _resolve_asset, _is_duplicate
from datetime import timedelta

text = open('sample_feeds/firewall.cef', encoding='utf-8').read()
fmt, records = feed_ingestor.parse(text, 'cef', 'Firewall')
print(f'Parsed {len(records)} records')

for rec in sorted(records, key=lambda r: r['timestamp']):
    print(f'\nProcessing: {rec["source_ip"]} / {rec["event_type"]}')
    try:
        dup = _is_duplicate(db, rec)
        print(f'  duplicate: {dup}')
        rec['asset_id'] = _resolve_asset(db, rec)
        print(f'  asset_id: {rec["asset_id"]}')
        res = pipeline.assess(
            db,
            source_ip=rec['source_ip'], event_type=rec['event_type'],
            severity=rec['severity'], asset_id=rec['asset_id'],
            timestamp=rec['timestamp'],
            raw_text=f"{rec.get('description') or ''} {rec.get('raw_log') or ''}",
            with_explanation=False,
        )
        print(f'  assess OK, risk={res["risk"]["risk_score"]}, verdict={res["verdict"]["verdict"]}')
        alert = pipeline.persist_new_alert(db, rec, res)
        db.flush()
        print(f'  persisted alert id={alert.id}')
    except Exception as e:
        print(f'  FAILED: {type(e).__name__}: {e}')
        traceback.print_exc()

try:
    db.commit()
    print('\nCommit OK')
except Exception as e:
    print(f'\nCommit FAILED: {e}')
    traceback.print_exc()
