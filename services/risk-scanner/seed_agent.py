"""Create (or reset) the first test agent account.
Run inside the container: python seed_agent.py <username> <password>
"""
import sys

from app.auth import hash_password
from app.db import SessionLocal, init_db
from app.models import AgentUser


def main():
    if len(sys.argv) != 3:
        print("Usage: python seed_agent.py <username> <password>")
        sys.exit(1)
    username, password = sys.argv[1], sys.argv[2]

    init_db()
    db = SessionLocal()
    try:
        agent = db.query(AgentUser).filter(AgentUser.username == username).first()
        if agent:
            agent.password_hash = hash_password(password)
            print(f"Password updated for existing agent '{username}'.")
        else:
            agent = AgentUser(username=username, password_hash=hash_password(password), display_name=username)
            db.add(agent)
            print(f"Agent '{username}' created.")
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    main()
