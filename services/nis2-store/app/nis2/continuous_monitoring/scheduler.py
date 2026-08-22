"""
Continuous Monitoring — APScheduler Background Job

Runs daily at 02:00 and scans all active targets whose next_scan_at is due.
Pattern mirrors crm/monitoring_scheduler.py.
"""

import logging
from datetime import UTC, datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

# Postgres advisory-lock key — ensures only ONE gunicorn worker runs the scan
# batch per fire, even though every worker starts its own scheduler. Arbitrary
# app-specific 32-bit constant ('NIS2' → 0x4E495332).
_MONITORING_LOCK_KEY = 0x4E495332


def init_nis2_monitoring_scheduler(app) -> BackgroundScheduler:
    """
    Start the NIS2 continuous monitoring scheduler.
    Runs daily at 02:00 AM (configurable via NIS2_MONITORING_HOUR).
    Returns the started scheduler so the caller can store it on app.
    """
    hour = int(app.config.get('NIS2_MONITORING_HOUR', 2))
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        _run_due_scans,
        trigger=CronTrigger(hour=hour, minute=0),
        args=[app],
        id='nis2_continuous_monitoring',
        name='NIS2 Continuous Compliance Monitoring',
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    logger.info('NIS2 monitoring scheduler started (daily at %02d:00)', hour)
    return scheduler


def _run_due_scans(app) -> None:
    """Check all active targets and scan those whose next_scan_at has arrived.

    Guarded by a Postgres advisory lock so that with multiple gunicorn workers
    only one actually runs the batch; the others exit immediately.
    """
    with app.app_context():
        lock_conn = _acquire_monitoring_lock(app)
        if lock_conn is False:
            logger.info('NIS2 monitoring: lock held by another worker — skipping')
            return
        try:
            _scan_due_targets()
        finally:
            _release_monitoring_lock(lock_conn)


def _scan_due_targets() -> None:
    try:
        from app.nis2.models import MonitoringTarget as MT
    except ImportError:
        return

    now = datetime.now(UTC)
    due_targets = MT.query.filter(
        MT.is_active == True,
        (MT.next_scan_at <= now) | (MT.next_scan_at == None),
    ).all()

    if not due_targets:
        logger.debug('NIS2 monitoring: no targets due for scan')
        return

    logger.info('NIS2 monitoring: scanning %d due target(s)', len(due_targets))

    from app.nis2.continuous_monitoring.scanner import run_scan_for_target
    for target in due_targets:
        try:
            run_scan_for_target(target, triggered_by='scheduler')
        except Exception:
            logger.exception('Scheduled scan failed for target %d (%s)',
                             target.id, target.domain)


def _acquire_monitoring_lock(app):
    """Try to grab the cross-worker advisory lock.

    Returns a dedicated held DB connection on success (keep it until release),
    False if another worker holds the lock, or None when locking is unavailable
    (non-Postgres / dev-SQLite) — in which case the caller proceeds unguarded.
    """
    uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if not uri.startswith('postgresql'):
        return None  # SQLite/dev: single worker, no lock needed

    from app.extensions import db
    try:
        conn = db.engine.raw_connection()
        cur = conn.cursor()
        cur.execute('SELECT pg_try_advisory_lock(%s)', (_MONITORING_LOCK_KEY,))
        acquired = cur.fetchone()[0]
        cur.close()
        if acquired:
            return conn  # held on a dedicated connection until _release
        conn.close()
        return False
    except Exception:
        logger.exception('Advisory lock acquire failed — proceeding unguarded')
        return None


def _release_monitoring_lock(lock_conn) -> None:
    if not lock_conn:  # None or False → nothing to release
        return
    try:
        cur = lock_conn.cursor()
        cur.execute('SELECT pg_advisory_unlock(%s)', (_MONITORING_LOCK_KEY,))
        cur.close()
    except Exception:
        logger.exception('Advisory lock release failed')
    finally:
        # Closing the connection releases the session-level lock regardless.
        try:
            lock_conn.close()
        except Exception:
            pass
