from .auth_log import AuthLogParser
from .nginx import NginxParser

REGISTRY = {
    "auth_log": AuthLogParser,
    "nginx": NginxParser,
}
