from server.app.conversation import ConversationManager
from server.app.providers import ProviderFactory
from server.app.cache import Cache

def test_conversation_manager_fallback():
    providers = ProviderFactory()
    cache = Cache(":memory:")
    conv = ConversationManager(providers, cache)

    # simple request analysis fallback (no SDKs required)
    res = conv.analyze_request("GET / HTTP/1.1\r\nHost:example\r\n\r\n")
    assert isinstance(res, dict)

    # response analysis fallback
    res2 = conv.analyze_response("HTTP/1.1 200 OK\r\n\r\n<html></html>")
    assert isinstance(res2, dict)

    # sqli generation fallback returns list or dict
    payloads = conv.generate_sqli("id", "mysql")
    assert isinstance(payloads, (list, dict))

    # jwt fallback using safe parser (use non-jwt string to check no exception)
    jwt_res = conv.analyze_jwt("not-a-jwt")
    assert isinstance(jwt_res, dict)
