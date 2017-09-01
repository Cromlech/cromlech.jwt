# -*- coding: utf-8 -*-

import uuid
import json
from .utils import get_posix_timestamp, expiration_date
from jwcrypto import jwk, jws, jwt
from jwcrypto.common import json_encode, json_decode


class JWTHandler(object):

    def __init__(self, auto_timeout=None):
        self.auto_timeout = auto_timeout

    def create_payload(self, **ticket):
        tid = uuid.uuid4()
        payload = {
            'uid': str(tid),
        }
        if self.auto_timeout is not None:
            exp = get_posix_timestamp(
                expiration_date(minutes=self.auto_timeout))
            payload['exp'] = int(exp)

        ticket.update(payload)
        return ticket

    @staticmethod
    def generate_key(self, ktype='oct', size=256):
        return jwk.JWK.generate(kty=ktype, size=size)

    def create_signed_token(self, key, payload, alg="HS256"):
        """Return an unserialized signed token. 
        Signed with the given key (JWK object)
        """
        token = jwt.JWT(header={"alg": alg}, claims=payload)
        token.make_signed_token(key)
        return token

    def create_encrypted_signed_token(
            self, key, payload, alg="A256KW", enc="A256CBC-HS512"):
        token = self.create_signed_token(key, payload)
        etoken = jwt.JWT(header={"alg": alg, "enc": enc},
                         claims=token.serialize())
        etoken.make_encrypted_token(key)
        return etoken

    def verify(self, key, serial):
        """Return the claims of a signed token.
        """
        ET = jwt.JWT(key=key, jwt=serial)
        return ET.claims

    def decrypt_and_verify(self, key, serial):
        """Return the claims of a signed and encrypted token.
        """
        eclaims = self.verify(key, serial)
        ST = jwt.JWT(key=key, jwt=eclaims)
        return ST.claims


class JWTService(object):

    def __init__(self, key, handler, lifetime=60, auto_deprecate=True):
        self.key = key
        self.lifetime = lifetime
        self.auto_deprecation = auto_deprecate and lifetime or None        
        self.handler = handler(auto_timeout=self.auto_deprecation)

    def check_token(self, payload):
        # Override for custom checks.
	return True

    def store(self, token):
        raise NotImplementedError(
            'Please override this method in a subclass.')

    def retrieve(self, *args):
        raise NotImplementedError(
            'Please override this method in a subclass.')
    
    def generate(self, payload):
        token = self.handler.create_encrypted_signed_token(self.key, payload)

    def refresh(self, *args):
        assert self.auto_deprecation is not None
        raise NotImplementedError(
            'Please override this method in a subclass.')

    def authenticate(self, credentials):
        """Returns a Principal object if credentials are valid
        """
        if not isinstance(credentials, dict):
            return None

        access_token = credentials.get('access_token')
        if access_token is None:
            return None

        payload = self.handler.decrypt_and_verify(self.key, access_token)
        if not payload:
            return None
        else:
            payload = json.loads(payload)

        if self.check_token(payload) == True:
            return AccessTokenHolder(payload)

        return None
