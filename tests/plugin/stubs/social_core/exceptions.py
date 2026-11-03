class AuthForbidden(Exception):
    def __init__(self, backend, *args):
        self.backend = backend
        super().__init__("refusé")
