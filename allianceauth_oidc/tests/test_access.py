import base64
import json
from types import SimpleNamespace
from urllib.parse import parse_qs

from allianceauth.authentication.models import State
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from allianceauth_oidc.auth_provider import AllianceAuthOAuth2Validator

from . import OIDCTestCase


class TestGeneratedEmailClaims(OIDCTestCase):
    def test_discovery_advertises_existing_claims(self):
        claims = AllianceAuthOAuth2Validator().get_discovery_claims(None)
        self.assertEqual(set(claims), {'sub', 'name', 'email', 'groups'})

    def test_email_claim_defaults_to_real_address(self):
        self.user1.email = 'private@example.com'
        request = SimpleNamespace(user=self.user1, scopes=['email'])

        claims = AllianceAuthOAuth2Validator().get_oidc_claims(None, None, request)

        self.assertEqual(claims['email'], 'private@example.com')

    @override_settings(ALLIANCEAUTH_OIDC_EMAIL_DOMAIN='example.invalid')
    def test_generated_email_is_scoped_and_omitted_without_main_character(self):
        validator = AllianceAuthOAuth2Validator()
        request = SimpleNamespace(user=self.user1, scopes=['openid'])
        self.assertNotIn('email', validator.get_oidc_claims(None, None, request))

        request.scopes.append('email')
        self.assertEqual(
            validator.get_oidc_claims(None, None, request)['email'], '1@example.invalid'
        )

        self.user4.email = 'private@example.com'
        request.user = self.user4
        self.assertNotIn('email', validator.get_oidc_claims(None, None, request))

    def test_invalid_generated_email_domain(self):
        request = self.factory.get('/')
        request.user = self.user1
        for domain in (
            'https://example.invalid',
            'user@example.invalid',
            'example.invalid/path',
            'example.invalid ',
            'example.invalid.',
            'localhost',
            123,
        ):
            with (
                self.subTest(domain=domain),
                override_settings(ALLIANCEAUTH_OIDC_EMAIL_DOMAIN=domain),
            ):
                with self.assertRaises(ImproperlyConfigured):
                    AllianceAuthOAuth2Validator().get_claim_dict(request)

    @override_settings(ALLIANCEAUTH_OIDC_EMAIL_DOMAIN='example.invalid')
    def test_generated_email_in_id_token_and_userinfo(self):
        self.user1.email = 'private@example.com'
        self.user1.save(update_fields=['email'])
        self.user1.user_permissions.add(self.access_oauth)
        self.client.force_login(self.user1)
        response = self.client.post(
            '/o/authorize/',
            data={
                'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': 'openid email',
                'state': 'generated-email',
                'allow': True,
            },
        )
        self.assertEqual(response.status_code, 302)
        code = parse_qs(response.headers['Location'].split('?')[1])['code'][0]
        response = self.client.post(
            '/o/token/',
            data={
                'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'client_secret': self.oauth_secret,
                'redirect_uri': 'http://localhost/redir/',
                'code': code,
            },
        )
        self.assertEqual(response.status_code, 200)
        tokens = response.json()
        encoded_claims = tokens['id_token'].split('.')[1]
        id_token_claims = json.loads(
            base64.urlsafe_b64decode(encoded_claims + '=' * (-len(encoded_claims) % 4))
        )
        self.assertEqual(id_token_claims['email'], '1@example.invalid')
        self.assertNotIn('private@example.com', response.content.decode())

        response = self.client.get(
            '/o/userinfo/', HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['email'], '1@example.invalid')
        self.assertNotIn('private@example.com', response.content.decode())


class TestCorptoolsCharAccessPerms(OIDCTestCase):

    def test_no_perms_oauth_u1(self):
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/')

        self.assertIn("External OAuth Denied",
                      response.content.decode("utf-8"))

    def test_with_perms_oauth_u1_all_scopes(self):
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': 'openid profile email',
                'state': "asdfghhjkl"
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(self.oauth_app.name, response.content.decode("utf-8"))
        self.assertIn(f"openid", response.content.decode("utf-8"))
        self.assertIn(f"email", response.content.decode("utf-8"))
        self.assertIn(f"profile", response.content.decode("utf-8"))

    def test_with_perms_oauth_u1_email_only(self):
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': 'email',
                'state': "asdfghhjkl"
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(self.oauth_app.name, response.content.decode("utf-8"))
        self.assertNotIn(f"openid", response.content.decode("utf-8"))
        self.assertIn(f"email", response.content.decode("utf-8"))
        self.assertNotIn(f"profile", response.content.decode("utf-8"))

    def test_with_perms_and_state_oauth_u1(self):
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': 'openid profile email',
                'state': "asdfghhjkl"
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(self.oauth_app.name, response.content.decode("utf-8"))
        self.assertIn(f"openid", response.content.decode("utf-8"))
        self.assertIn(f"email", response.content.decode("utf-8"))
        self.assertIn(f"profile", response.content.decode("utf-8"))

    def test_full_chain_u1_with_perms_and_state(self):
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])

        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEqual(scopes, get_params['scope'])
        self.assertEqual(60, get_params['expires_in'])

    def test_full_chain_u1_with_perms_and_wrong_state(self):
        self.oauth_app.states.add(State.objects.get(name="Guest"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(f"{self.oauth_app} Access Denied",
                      response.content.decode("utf-8"))
        self.assertEqual(200, response.status_code)

    def test_full_chain_u1_with_perms_and_wrong_state_and_group(self):
        self.oauth_app.states.add(State.objects.get(name="Guest"))
        self.oauth_app.groups.add(self.test_grp)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])

        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEqual(scopes, get_params['scope'])
        self.assertEqual(60, get_params['expires_in'])

    def test_full_chain_u1_with_perms_and_group_and_state(self):
        self.oauth_app.groups.add(self.test_grp)
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_group_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])
        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEqual(scopes, get_params['scope'])
        self.assertEqual(60, get_params['expires_in'])

    def test_full_chain_u1_with_perms_and_group(self):
        self.oauth_app.groups.add(self.test_grp)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_group"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])
        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEqual(scopes, get_params['scope'])
        self.assertEqual(60, get_params['expires_in'])

    def test_full_chain_u1_with_perms_and_wrong_group(self):
        self.oauth_app.groups.add(self.test_grp_2)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_group"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(f"{self.oauth_app} Access Denied",
                      response.content.decode("utf-8"))
        self.assertEqual(200, response.status_code)

    def test_full_chain_u1_with_perms_and_wrong_group_and_state(self):
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.oauth_app.groups.add(self.test_grp_2)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_group_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])
        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEqual(scopes, get_params['scope'])
        self.assertEqual(60, get_params['expires_in'])

    def test_get_u1_without_perms_and_group_and_state(self):
        self.oauth_app.groups.add(self.test_grp)
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_get_u1_without_perms_and_group_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.get('/o/authorize/', data=data)
        self.assertIn(f"{self.oauth_app} Access Denied",
                      response.content.decode("utf-8"))
        self.assertEqual(200, response.status_code)

    def test_full_chain_u1_with_su(self):
        # wrong state to test bypass for SU
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.is_superuser = True
        self.user1.save()
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = 'openid profile email'
        data = {'response_type': 'code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'scope': scopes,
                'state': state,
                'allow': True
                }
        self.client.force_login(self.user1)
        response = self.client.post('/o/authorize/', data=data)
        get_params = parse_qs(response.headers['Location'].split("?")[1])

        self.assertIn("code", get_params)
        self.assertIn(f"state={state}", response.headers['Location'])

        data = {'grant_type': 'authorization_code',
                'client_id': self.oauth_id,
                'redirect_uri': 'http://localhost/redir/',
                'client_secret': self.oauth_secret,
                'state': state,
                'code': get_params['code'][0]
                }
        response = self.client.post('/o/token/', data=data)
        get_params = json.loads(response.content.decode("utf-8"))

        self.assertIn("access_token", get_params)
        self.assertIn("refresh_token", get_params)
        self.assertIn("id_token", get_params)
        self.assertEqual(scopes, get_params['scope'])
        self.assertEqual(60, get_params['expires_in'])
