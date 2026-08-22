from slowapi import Limiter

from app.security import client_ip

limiter = Limiter(key_func=client_ip)
