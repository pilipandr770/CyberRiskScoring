"""
Super-Admin Dashboard — all users, payments, token usage.
Protected: is_admin=True required.
"""

from datetime import UTC, datetime, timedelta

from flask import abort, render_template
from flask_login import current_user, login_required
from sqlalchemy import func

from app.extensions import db
from app.models import User
from app.nis2.models import APIUsageLog

from . import admin_bp


def _require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


# ── Dashboard overview ────────────────────────────────────────────

@admin_bp.route('/')
@login_required
def dashboard():
    _require_admin()

    now = datetime.now(UTC)
    month_ago = now - timedelta(days=30)

    # ── User stats ────────────────────────────────────────────────
    total_users = User.query.count()
    new_this_month = User.query.filter(User.created_at >= month_ago).count()
    active_trials = User.query.filter_by(subscription_plan='trial').count()
    basic_count = User.query.filter_by(subscription_plan='basic').count()
    professional_count = User.query.filter_by(subscription_plan='professional').count()
    enterprise_count = User.query.filter_by(subscription_plan='enterprise').count()

    # ── Revenue estimate (MRR) ────────────────────────────────────
    mrr = basic_count * 49 + professional_count * 149 + enterprise_count * 0

    # ── Token usage totals ────────────────────────────────────────
    total_input = db.session.query(func.sum(APIUsageLog.input_tokens)).scalar() or 0
    total_output = db.session.query(func.sum(APIUsageLog.output_tokens)).scalar() or 0

    # Usage by model
    by_model = db.session.query(
        APIUsageLog.model,
        func.sum(APIUsageLog.input_tokens).label('input_tokens'),
        func.sum(APIUsageLog.output_tokens).label('output_tokens'),
        func.count(APIUsageLog.id).label('calls'),
    ).group_by(APIUsageLog.model).all()

    # Usage by endpoint
    by_endpoint = db.session.query(
        APIUsageLog.endpoint,
        func.sum(APIUsageLog.input_tokens).label('input_tokens'),
        func.sum(APIUsageLog.output_tokens).label('output_tokens'),
        func.count(APIUsageLog.id).label('calls'),
    ).group_by(APIUsageLog.endpoint).all()

    # Top 10 users by token consumption
    top_users = db.session.query(
        APIUsageLog.user_id,
        func.sum(APIUsageLog.input_tokens + APIUsageLog.output_tokens).label('total_tokens'),
        func.count(APIUsageLog.id).label('calls'),
    ).group_by(APIUsageLog.user_id).order_by(
        func.sum(APIUsageLog.input_tokens + APIUsageLog.output_tokens).desc()
    ).limit(10).all()

    top_users_enriched = []
    for row in top_users:
        user = db.session.get(User, row.user_id) if row.user_id else None
        top_users_enriched.append({
            'user': user,
            'total_tokens': row.total_tokens,
            'calls': row.calls,
        })

    # Recent logs (last 50)
    recent_logs = APIUsageLog.query.order_by(
        APIUsageLog.created_at.desc()
    ).limit(50).all()

    return render_template(
        'admin/dashboard.html',
        total_users=total_users,
        new_this_month=new_this_month,
        active_trials=active_trials,
        basic_count=basic_count,
        professional_count=professional_count,
        enterprise_count=enterprise_count,
        mrr=mrr,
        total_input=total_input,
        total_output=total_output,
        by_model=by_model,
        by_endpoint=by_endpoint,
        top_users=top_users_enriched,
        recent_logs=recent_logs,
        now=now,
    )


# ── Users list ────────────────────────────────────────────────────

@admin_bp.route('/users')
@login_required
def users():
    _require_admin()
    all_users = User.query.order_by(User.created_at.desc()).all()

    # Attach token totals per user
    usage_map = {}
    rows = db.session.query(
        APIUsageLog.user_id,
        func.sum(APIUsageLog.input_tokens + APIUsageLog.output_tokens).label('tokens'),
        func.count(APIUsageLog.id).label('calls'),
    ).group_by(APIUsageLog.user_id).all()
    for r in rows:
        usage_map[r.user_id] = {'tokens': r.tokens or 0, 'calls': r.calls or 0}

    return render_template(
        'admin/users.html',
        users=all_users,
        usage_map=usage_map,
    )


# ── Blog management ───────────────────────────────────────────────

@admin_bp.route('/blog')
@login_required
def blog_posts():
    _require_admin()
    from blog.models import BlogPost
    posts = BlogPost.query.order_by(BlogPost.created_at.desc()).limit(100).all()
    return render_template('admin/blog_posts.html', posts=posts)


@admin_bp.route('/blog/<int:post_id>/toggle', methods=['POST'])
@login_required
def blog_toggle(post_id):
    _require_admin()
    from blog.models import BlogPost
    from flask import redirect, url_for, flash
    post = db.session.get(BlogPost, post_id)
    if not post:
        abort(404)
    post.is_published = not post.is_published
    if post.is_published and not post.published_at:
        from datetime import UTC, datetime
        post.published_at = datetime.now(UTC)
    db.session.commit()
    flash(f'Artikel {"veröffentlicht" if post.is_published else "zurückgezogen"}.', 'success')
    return redirect(url_for('admin.blog_posts'))


@admin_bp.route('/blog/trigger-news', methods=['POST'])
@login_required
def blog_trigger_news():
    """Start news-fetch job in a background thread and return immediately.

    The Anthropic API call takes 30-120 s — running it synchronously kills
    the gunicorn worker (timeout).  We fire-and-forget into a daemon thread
    instead; the result appears in the blog list after a few seconds.
    """
    _require_admin()
    import threading
    from flask import redirect, url_for, flash, current_app
    app = current_app._get_current_object()

    def _run():
        from blog.scheduler import trigger_news_now
        trigger_news_now(app)

    threading.Thread(target=_run, daemon=True).start()
    flash('News-Job gestartet — Artikel erscheint in ~60 Sekunden in der Liste.', 'info')
    return redirect(url_for('admin.blog_posts'))


@admin_bp.route('/blog/trigger-evergreen', methods=['POST'])
@login_required
def blog_trigger_evergreen():
    """Start evergreen-generation job in a background thread and return immediately.

    Generating a full 1200-word article via Anthropic takes 30-120 s — too
    long for a synchronous HTTP request.  We fire-and-forget into a daemon
    thread; the new article shows up in the list once it finishes.
    """
    _require_admin()
    import threading
    from flask import redirect, url_for, flash, current_app
    app = current_app._get_current_object()

    def _run():
        from blog.scheduler import trigger_evergreen_now
        trigger_evergreen_now(app)

    threading.Thread(target=_run, daemon=True).start()
    flash('Evergreen-Artikel wird generiert — erscheint in ~60–90 Sekunden in der Liste.', 'info')
    return redirect(url_for('admin.blog_posts'))
