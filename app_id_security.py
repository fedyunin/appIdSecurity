# Google Appengine Application ID security.
# Decorator for secure inter-app communication. Just check if caller app id included to allowed access list.
#
# Decorator:
# @appIdSecurity(allowedAppIds)
# - where allowedAppIds is list of appIds which allowed to make requests.
#
# Example of allowedAppIds:
# allowedAppIds={"appId1","appId2"}
#
# For skip app id security just add '*' to allowedAppIds
#
# Alexey Fedyunin alexey@cranfan.ru

import logging

# Symbol used for detect that need skip security check
from webapp2 import Response

SKIP_SECURITY_SYMBOL = '*'

X_APP_ENGINE_INBOUND_APP_ID = "X-AppEngine-Inbound-AppId"



# Security error. Will raise if security check was unsuccessfully.
class SecurityError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# decorator
def appIdSecurity(allowedAppIds):
    def decorator(view_func):
        def wrapper(parent, *args, **kwargs):
            logging.info("appIdSecurity: Checking security...")
            request = parent.request
            logging.info("appIdSecurity: Request body: %s" % request.body)
            result = Response()
            try:
                checkCallerApplicationId(request, allowedAppIds)
                result = view_func(parent, *args, **kwargs)
                return result
            except SecurityError as se:
                result.status = 403
                result.body = se.value
                return result

        return wrapper

    return decorator


# checks that app id value in request header exists in the allowedAppIds list.
def checkCallerApplicationId(request, allowedAppIds):
    logging.info("appIdSecurity: Check caller app id")
    if SKIP_SECURITY_SYMBOL in allowedAppIds:
        logging.info("appIdSecurity: Skip check. Cause '%s' in the allowed app ids." % SKIP_SECURITY_SYMBOL)
        return
    try:
        callerAppId = request.headers[X_APP_ENGINE_INBOUND_APP_ID]
    except:
        msg = "Unknown caller Application ID. Unable to complete request." \
              "\n Probably request received from non GAE application or your app running on development server." \
              "\n You can use symbol '%s' in your allowedAppIds for skip security check." % SKIP_SECURITY_SYMBOL
        logging.error("appIdSecurity: %s" % msg)
        raise SecurityError(msg)

    logging.info("appIdSecurity: Caller AppId: %s" % callerAppId)
    #check caller app id
    if not callerAppId in allowedAppIds:
        msg = "Not allowed remote Application ID:'%s' not included in the list of granted access app IDs." % callerAppId
        logging.error("appIdSecurity: %s" % msg)
        raise SecurityError(msg)
