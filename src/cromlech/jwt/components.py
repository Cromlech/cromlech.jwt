import uuid
import json
from .utils import get_posix_timestamp, expiration_date
from jwcrypto import jwk, jwt, jwe, jws
from jwcrypto.common import json_decode
from jwcrypto.jwe import InvalidJWEData
from jwcrypto.jwt import JWTExpired


class TokenException(Exception):

    def __init__(self, token):
        self.token = token


class InvalidToken(TokenException):

    def __str__(self):
        return f"Token {self.token} could not be parse and/or interpreted."


class ExpiredToken(TokenException):

    def __str__(self):
        return "Token {self.token} is expired."


class InvalidPayload(Exception):
    pass


class JWTHandler:

    @staticmethod
    def generate_uid():
        return str(uuid.uuid4())

    @staticmethod
    def generate_key(kty='oct', size=256):
        return jwk.JWK.generate(kty=kty, size=size)

    @staticmethod
    def dump_key(key):
        """The result of the export is a JSON string
        """
        return key.export()

    @staticmethod
    def load_key(key_string):
        key_data = json.loads(key_string)
        return jwk.JWK(**key_data)

    def __init__(self, auto_timeout=None):
        self.auto_timeout = auto_timeout

    def create_payload(self, **data):
        if self.auto_timeout is None and 'exp' in data:
            # No self-deprecation allowed.
            raise InvalidPayload('Expiration is not allowed.')

        payload = {
            'uid': self.generate_uid(),
        }

        if self.auto_timeout is not None:
            exp = get_posix_timestamp(
                expiration_date(minutes=self.auto_timeout))
            payload['exp'] = int(exp)

        payload.update(data)
        return payload

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
        ET = jwt.JWT(key=key, jwt=serial, expected_type="JWE")
        return ET.claims

    def decrypt_and_verify(self, key, serial):
        """Return the claims of a signed and encrypted token.
        """
        eclaims = self.verify(key, serial)
        try:
            ST = jwt.JWT(key=key, jwt=eclaims)
        except JWTExpired:
            raise ExpiredToken(serial)
        return ST.claims


class JWTService:

    def __init__(self, key, handler, lifetime=60, auto_deprecate=True):
        self.key = key
        self.lifetime = lifetime  # Lifetime might be used in store or refresh
        self.auto_deprecation = auto_deprecate and lifetime or None
        self.handler = handler(auto_timeout=self.auto_deprecation)

    def check_data(self, payload):
        return True  # Override for custom checks

    def store(self, token):
        raise NotImplementedError(
            'Please override this method in a subclass.')

    def retrieve(self, *args):
        raise NotImplementedError(
            'Please override this method in a subclass.')

    def generate(self, data):
        payload = self.handler.create_payload(**data)
        token = self.handler.create_encrypted_signed_token(self.key, payload)
        return token.serialize()

    def refresh(self, *args):
        assert self.auto_deprecation is not None
        raise NotImplementedError(
            'Please override this method in a subclass.')

    def check_token(self, token):
        """Returns a Principal object if credentials are valid
        """
        if token is None:
            return None

        try:
            payload = self.handler.decrypt_and_verify(self.key, token)
        except InvalidJWEData:
            raise InvalidToken(token)

        if payload:
            data = json_decode(payload)
            if self.check_data(data) == True:
                return data

        return None
