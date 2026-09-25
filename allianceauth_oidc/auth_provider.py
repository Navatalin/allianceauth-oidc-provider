from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.validators import DomainNameValidator
from oauth2_provider.oauth2_validators import OAuth2Validator


class AllianceAuthOAuth2Validator(OAuth2Validator):
    # Extend the standard scopes to add a new "permissions" scope
    # which returns a "permissions" claim:
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update({"groups": "profile"})

    def _load_application(self, client_id, request):
        client = super()._load_application(client_id, request)
        return client

    def get_discovery_claims(self, request):
        return ['sub', 'name', 'email', 'groups']

    def get_additional_claims(self, request):
        out = {
            "name": lambda request: request.user.profile.main_character.character_name,
            "groups": lambda request: list(request.user.groups.all().values_list('name', flat=True)) + [request.user.profile.state.name]
        }
        domain = getattr(settings, 'ALLIANCEAUTH_OIDC_EMAIL_DOMAIN', None)
        if domain is None or domain == '':
            out['email'] = lambda request: request.user.email
        else:
            if not isinstance(domain, str) or domain.endswith('.'):
                raise ImproperlyConfigured('ALLIANCEAUTH_OIDC_EMAIL_DOMAIN must be a bare domain name')
            try:
                DomainNameValidator(accept_idna=False)(domain)
            except ValidationError as error:
                raise ImproperlyConfigured('ALLIANCEAUTH_OIDC_EMAIL_DOMAIN must be a bare domain name') from error
            if request.user.profile.main_character is not None:
                out['email'] = lambda request: f"{request.user.profile.main_character.character_id}@{domain}"
        return out
