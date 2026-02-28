"""Shared SlowAPI limiter instance.

Defining the limiter in a dedicated module lets routers import and apply
rate-limit decorators without depending on app.main (which would create a
circular import: main → routers → main).
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
