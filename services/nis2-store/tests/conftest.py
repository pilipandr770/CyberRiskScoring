import os

# Must be set before any app import so models use no schema (SQLite-compatible).
# load_dotenv() uses override=False by default, so this wins over .env values.
os.environ['DB_SCHEMA'] = ''

import pytest

from app import create_app
from app.extensions import db


@pytest.fixture()
def flask_app():
    flask_app = create_app("testing")
    flask_app.config.update(
        MAIL_SUPPRESS_SEND=True,
        SERVER_NAME="localhost",
    )

    with flask_app.app_context():
        # Ensure all models are registered before table creation.
        import app.nis2.models  # noqa: F401

        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()
