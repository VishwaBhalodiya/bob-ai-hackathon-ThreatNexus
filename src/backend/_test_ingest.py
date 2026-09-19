import sys, traceback
sys.path.insert(0, '.')
from database import get_db, ensure_schema
ensure_schema()
db = next(get_db())
from services import feed_ingestor, pipeline
from models import Alert, Asset, IOC

samples = [
    ('sample_feeds/firewall.cef',          'cef',    'Firewall'),
    ('sample_feeds/ids_suricata.log',       'syslog', 'IDS/IPS'),
    ('sample_feeds/siem_export.json',       'json',   'SIEM'),
    ('sample_feeds/edr_detections.csv',     'csv',    'EDR'),
    ('sample_feeds/threat_intel.stix.json', 'stix',   'Threat Intel Feed'),
]

for path, fmt, src in samples:
    try:
        text = open(path, encoding='utf-8').read()
        f, records = feed_ingestor.parse(text, fmt, src)
        print(f'OK  {path}: {len(records)} records')
        if f != 'stix' and records:
            r = records[0]
            res = pipeline.assess(
                db, source_ip=r['source_ip'], event_type=r['event_type'],
                severity=r['severity'], raw_text=r.get('raw_log', ''),
                with_explanation=False,
            )
            print(f'    assess OK, risk={res["risk"]["risk_score"]}')
    except Exception as e:
        print(f'FAIL {path}: {type(e).__name__}: {e}')
        traceback.print_exc()

print()
print('Done.')
