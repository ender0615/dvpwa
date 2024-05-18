from uuid import uuid4
from aiohttp_session import get_session
from sqli.utils.auth import get_auth_user

async def csrf_processor(request):
    session = await get_session(request)
    if '_csrf_token' not in session:
        session['_csrf_token'] = uuid4().hex
    return {'csrf_token': session['_csrf_token']}

async def auth_user_processor(request):
    auth_user = await get_auth_user(request)
    return {'auth_user': auth_user}
