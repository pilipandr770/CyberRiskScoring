"""
Blog blueprint — public cybersecurity blog for NIS2 Compliance Platform.

Routes:
  /blog/                → latest articles, paginated
  /blog/<slug>          → single article
  /blog/tag/<tag-slug>  → articles filtered by tag
  /blog/feed.xml        → RSS feed (SEO + readers)
"""

from flask import Blueprint

blog_bp = Blueprint('blog', __name__, template_folder='../templates/blog')

from blog import routes  # noqa — registers all route handlers
