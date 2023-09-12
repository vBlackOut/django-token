from django import http
from django.contrib.auth import login
from django.core import exceptions
from .backends import TokenBackend

class TokenMiddleware(object):
    """
    Middleware that authenticates against a token in the http authorization
    header.
    """
    get_response = None

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        #self.get_response = get_response

        #if not self.get_response:
        #    return exceptions.ImproperlyConfigured(
        #        'Middleware called without proper initialization')
        self.process_request(request)
        return self.get_response(request)

    def process_request(self, request):
        #self.get_response = get_response

        auth_header = str(request.META.get('HTTP_AUTHORIZATION', '')).partition(' ')

        if auth_header[0].lower() != 'token':
            return None

        # If they specified an invalid token, let them know.
        if not auth_header[2]:
            return http.HttpResponseBadRequest("Improperly formatted token")
        
        user = TokenBackend().authenticate(token=auth_header[2])
        print(f"token: {user}")
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        
        if user:
            request.user = user
