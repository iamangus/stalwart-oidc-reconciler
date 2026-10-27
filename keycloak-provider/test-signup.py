#!/usr/bin/env python3
"""Destructive ONLY to the disposable local apps realm at 127.0.0.1:18880.

Exercises the exact deployment CLI declarations, native invitation binding,
registration denial, immutable username, protected claim publication, mailbox
login and native password-recovery delivery. SMTP is captured in memory; no
message leaves this machine. Requires requests and Playwright/Chromium.
"""
import argparse
import asyncio
import email
import html
import os
from pathlib import Path
import queue
import re
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlencode

import requests
from playwright.sync_api import sync_playwright

BASE = 'http://127.0.0.1:18880/auth'
messages = queue.Queue()


async def smtp(reader, writer):
    async def reply(text):
        writer.write((text + '\r\n').encode())
        await writer.drain()
    await reply('220 local-test ESMTP')
    recipients = []
    while line := await reader.readline():
        command = line.decode().strip()
        if command.startswith(('EHLO', 'HELO')):
            await reply('250 local-test')
        elif command.startswith('RCPT TO:'):
            recipients.append(command[8:].strip())
            await reply('250 OK')
        elif command == 'DATA':
            await reply('354 End with dot')
            body = bytearray()
            while (line := await reader.readline()) != b'.\r\n':
                if not line:
                    return
                body.extend(line)
            messages.put((recipients[:], email.message_from_bytes(bytes(body))))
            recipients.clear()
            await reply('250 OK')
        elif command == 'QUIT':
            await reply('221 Bye')
            break
        else:
            await reply('250 OK')
    writer.close()


def smtp_thread():
    async def run():
        server = await asyncio.start_server(smtp, '127.0.0.1', 18025)
        async with server:
            await server.serve_forever()
    asyncio.run(run())


def message_link(expected):
    recipients, message = messages.get(timeout=15)
    assert recipients == ['<' + expected + '>'], recipients
    texts = []
    for part in message.walk():
        if part.get_content_type() in ('text/plain', 'text/html'):
            texts.append(part.get_payload(decode=True).decode())
    links = re.findall(r'http://127\.0\.0\.1:18880/[^\s<>"\]]+', html.unescape('\n'.join(texts)))
    return next(link for link in links if '/login-actions/' in link or '/protocol/openid-connect/registrations' in link)


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--plan', required=True, type=Path)
    args.add_argument('--keycloak-home', required=True, type=Path)
    args.add_argument('--admin-password-file', required=True, type=Path)
    args = args.parse_args()
    threading.Thread(target=smtp_thread, daemon=True).start()
    for _ in range(90):
        try:
            if requests.get(BASE + '/realms/master', timeout=2).ok:
                break
        except requests.RequestException:
            pass
        time.sleep(1)
    response = requests.post(BASE + '/realms/master/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'admin',
        'password': args.admin_password_file.read_text()}, timeout=10)
    response.raise_for_status()
    admin = requests.Session()
    admin.headers['Authorization'] = 'Bearer ' + response.json()['access_token']

    def api(method, path, **kwargs):
        response = admin.request(method, BASE + '/admin/realms/' + path, timeout=15, **kwargs)
        response.raise_for_status()
        return response

    # This is an isolated test fixture, never deployment provisioning.
    old = admin.get(BASE + '/admin/realms/apps', timeout=10)
    if old.ok:
        api('DELETE', 'apps')
    response = admin.post(BASE + '/admin/realms', json={
        'realm': 'apps', 'enabled': True, 'sslRequired': 'none',
        'smtpServer': {'host': '127.0.0.1', 'port': '18025', 'from': 'accounts@srvd.dev'}}, timeout=15)
    response.raise_for_status()
    with tempfile.TemporaryDirectory(prefix='signup-cli-', dir='/tmp/opencode') as work:
        env = dict(os.environ, SIGNUP_WORK_DIR=work, SIGNUP_PLAN_DIR=str(args.plan.resolve()),
                   KC_CLI=str(args.keycloak_home.resolve() / 'bin/kcadm.sh'),
                   KC_TEST_PASSWORD=args.admin_password_file.read_text())
        command = '''set -eu
kc() { "$KC_CLI" "$@" --config "$SIGNUP_WORK_DIR/kcadm.config"; }
ids() { sed '/^id$/d; /^[[:space:]]*$/d'; }
kc config credentials --server http://127.0.0.1:18880/auth --realm master --user admin --password "$KC_TEST_PASSWORD"
. "$SIGNUP_PLAN_DIR/signup.sh"
'''
        for _ in range(2):
            result = subprocess.run(['sh', '-c', command], env=env, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
    realm = api('GET', 'apps').json()
    assert not realm['registrationAllowed'] and not realm['editUsernameAllowed']
    organization = realm['attributes']['srvdMailOrganizationId']
    assert api('GET', f'apps/organizations/{organization}').json().get('domains', []) == []
    # Dedicated publisher: no realm-management roles, only the restricted claim role.
    api('POST', 'apps/roles', json={'name': 'srvd-mail-publish'})
    publisher_secret = secrets.token_hex(24)
    client = {'clientId': 'stalwart-mail-publisher', 'enabled': True,
              'secret': publisher_secret, 'serviceAccountsEnabled': True,
              'standardFlowEnabled': False, 'directAccessGrantsEnabled': False,
              'fullScopeAllowed': False, 'defaultClientScopes': ['roles']}
    publisher = api('POST', 'apps/clients', json=client).headers['Location'].rsplit('/', 1)[1]
    service = api('GET', f'apps/clients/{publisher}/service-account-user').json()['id']
    role = api('GET', 'apps/roles/srvd-mail-publish').json()
    api('POST', f'apps/users/{service}/role-mappings/realm', json=[role])
    api('POST', f'apps/clients/{publisher}/scope-mappings/realm', json=[role])
    token = requests.post(BASE + '/realms/apps/protocol/openid-connect/token', data={
        'grant_type': 'client_credentials', 'client_id': client['clientId'], 'client_secret': publisher_secret}, timeout=10)
    token.raise_for_status()
    writer = {'Authorization': 'Bearer ' + token.json()['access_token']}
    recovery = 'signup-test@example.net'
    api('POST', f'apps/organizations/{organization}/members/invite-user', data={'email': recovery})
    invitation = message_link(recovery)
    password = secrets.token_urlsafe(24)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        account_tokens = []
        def account_request(request):
            authorization = request.headers.get('authorization', '')
            if '/realms/apps/account' in request.url and authorization.startswith('Bearer '):
                account_tokens.append(authorization)
        page.on('request', account_request)
        public_url = BASE + '/realms/apps/protocol/openid-connect/registrations?' + urlencode({
            'client_id': 'account-console', 'redirect_uri': BASE + '/realms/apps/account/',
            'response_type': 'code', 'scope': 'openid', 'code_challenge': 'a' * 43, 'code_challenge_method': 'S256'})
        page.goto(public_url)
        assert page.locator('#username').count() == 0, 'public registration opened'
        page.goto(invitation)
        page.locator('#username').wait_for()
        assert page.locator('#email').input_value() == recovery
        assert page.locator('#email').is_disabled() or not page.locator('#email').is_editable()
        page.locator('#username').fill('pseudonym')
        page.locator('#firstName').fill('Signup')
        page.locator('#lastName').fill('Test')
        # Removing readonly in developer tools must not change the invitation's
        # authority. The stock server rejects a different recovery email.
        page.locator('#email').evaluate("e => { e.readOnly = false; e.value = 'attacker@example.net'; }")
        page.get_by_role('button', name='Register', exact=True).click()
        page.get_by_text('Email does not match the invitation', exact=False).wait_for()
        assert api('GET', 'apps/users', params={'username': 'pseudonym', 'exact': 'true'}).json() == []
        page.locator('#email').evaluate("(e, value) => { e.value = value; }", recovery)
        page.get_by_role('button', name='Register', exact=True).click()
        page.wait_for_load_state('networkidle')
        partial = api('GET', 'apps/users', params={'username': 'pseudonym', 'exact': 'true'}).json()[0]
        partial_url = BASE + f'/realms/apps/srvd-mail/users/{partial["id"]}/address'
        assert requests.put(partial_url, headers=writer, json={'address': 'signup.test@srvd.dev'}, timeout=10).status_code == 403
        if page.locator('#password-new').count() == 0:
            page.goto(message_link(recovery))
        page.locator('#password-new').wait_for()
        page.locator('#password-new').fill(password)
        page.locator('#password-confirm').fill(password)
        page.get_by_role('button', name='Submit', exact=True).click()
        page.wait_for_url('**/realms/apps/account/**')
        page.get_by_role('link', name='Personal info', exact=True).wait_for()
        page.wait_for_load_state('networkidle')
        user = api('GET', 'apps/users', params={'username': 'pseudonym', 'exact': 'true'}).json()[0]
        assert user['email'] == recovery and user['emailVerified'] and user['requiredActions'] == []
        uid = user['id']
        assert [x['id'] for x in api('GET', f'apps/organizations/{organization}/members').json()] == [uid]
        address_url = BASE + f'/realms/apps/srvd-mail/users/{uid}/address'
        assert requests.put(address_url, json={'address': 'signup.test@srvd.dev'}, timeout=10).status_code == 401
        for _ in range(2):
            assert requests.put(address_url, headers=writer, json={'address': 'signup.test@srvd.dev'}, timeout=10).status_code == 204
        assert requests.put(address_url, headers=writer, json={'address': 'other@srvd.dev'}, timeout=10).status_code == 409
        assert requests.get(BASE + '/admin/realms/apps/users', headers=writer, timeout=10).status_code == 403
        page.reload()
        page.get_by_role('link', name='Personal info', exact=True).click()
        page.wait_for_function("() => document.body.textContent.includes('signup.test@srvd.dev') || [...document.querySelectorAll('input')].some(e => e.value === 'signup.test@srvd.dev')")
        assert account_tokens
        user_headers = {'Authorization': account_tokens[-1], 'Origin': 'http://127.0.0.1:18880'}
        assert requests.put(address_url, headers=user_headers, json={'address': 'evil@srvd.dev'}, timeout=10).status_code == 403
        requests.post(BASE + '/realms/apps/account/', headers=user_headers, json={
            'username': 'renamed', 'firstName': 'Signup', 'lastName': 'Test', 'email': recovery,
            'attributes': {'mail_address': ['evil@srvd.dev']}}, timeout=10)
        unchanged = api('GET', f'apps/users/{uid}').json()
        assert unchanged['username'] == 'pseudonym' and unchanged['attributes']['mail_address'] == ['signup.test@srvd.dev']
        # Fresh context proves alias resolution, not an existing SSO cookie.
        fresh = browser.new_context()
        login = fresh.new_page()
        login.goto(BASE + '/realms/apps/account/')
        login.locator('#username').fill('signup.test@srvd.dev')
        login.locator('#password').fill(password)
        login.get_by_role('button', name='Sign In', exact=True).click()
        login.wait_for_url('**/realms/apps/account/**')
        reset = browser.new_context().new_page()
        reset.goto(BASE + '/realms/apps/account/')
        reset.get_by_role('link', name='Forgot Password?').click()
        reset.locator('#username').fill('signup.test@srvd.dev')
        reset.get_by_role('button', name='Submit', exact=True).click()
        message_link(recovery)
        # Native UPDATE_EMAIL requires password reauthentication and retains the
        # old recovery address until the verification link is redeemed.
        update_url = BASE + '/realms/apps/protocol/openid-connect/auth?' + urlencode({
            'client_id': 'account-console', 'redirect_uri': BASE + '/realms/apps/account/',
            'response_type': 'code', 'scope': 'openid', 'code_challenge': 'b' * 43,
            'code_challenge_method': 'S256', 'kc_action': 'UPDATE_EMAIL'})
        login.goto(update_url)
        login.locator('#password').wait_for()
        login.locator('#password').fill(password)
        login.get_by_role('button', name='Sign In', exact=True).click()
        login.locator('#email').wait_for()
        login.locator('#email').fill('new-recovery@example.net')
        login.get_by_role('button', name='Submit', exact=True).click()
        verification = message_link('new-recovery@example.net')
        assert api('GET', f'apps/users/{uid}').json()['email'] == recovery
        login.goto(verification)
        updated = api('GET', f'apps/users/{uid}').json()
        assert updated['email'] == 'new-recovery@example.net' and updated['emailVerified']
        assert updated['attributes']['mail_address'] == ['signup.test@srvd.dev']
        # Used invite must not create another account.
        replay = browser.new_context().new_page()
        replay.goto(invitation)
        assert replay.locator('#kc-register-form').count() == 0
        browser.close()
    print('PASS isolated native invitation/signup, immutable realm policy, read-only primary email, restricted/idempotent publication, mailbox login and external reset delivery')


if __name__ == '__main__':
    main()
