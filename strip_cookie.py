from burp import IBurpExtender
from burp import IHttpListener

#
# Generic extension to strip a cookie from a request in all tools.
#

COOKIE_NAME = 'COOKIE'


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Strip Cookie')
        callbacks.registerHttpListener(self)

        return

    def _processCookies(self, cookieString):
        cookies = [c.strip(' ') for c in cookieString.split(';')]
        print cookies
        print ''
        for cookie in cookies[:]:
            if cookie.startswith(COOKIE_NAME):
                cookies.remove(cookie)

        return ';'.join(cookies)

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        if messageIsRequest:
            requestInfo = self._helpers.analyzeRequest(currentMessage)
            headers = requestInfo.getHeaders()
            msgBody = currentMessage.getRequest()[requestInfo.getBodyOffset():]
            newCookies = ''

            # Process the current cookies to remove the one we don't want.
            for header in headers[:]:
                if header.startswith('Cookie: '):
                    newCookies = self._processCookies(header[8:])

            print newCookies
            print ''

            # Replace the current Cookie header with the new one.
            for header in headers[:]:
                if header.startswith('Cookie: '):
                    headers.remove(header)
                    headers.add('Cookie: {0}'.format(newCookies))

            # Build new message with the new header
            message = self._helpers.buildHttpMessage(headers, msgBody)

            # Print headers to UI. Enable this for debugging.
            # print '\r\n'.join(headers)
            # print ''

            # Update request with new headers
            currentMessage.setRequest(message)

        return
