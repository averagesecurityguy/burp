from burp import IBurpExtender
from burp import IHttpListener

#
# Generic extension to copy the value of a cookie to a header. I needed it to
# deal with a CSRF issue, but it can be used to move any cookie value to a
# header. Just supply the cookie name and header name below. The basis of the
# script was taken from here:
# https://www.fishnetsecurity.com/6labs/blog/automatically-adding-new-header-burp
#

COOKIE_NAME = 'XSRF-TOKEN'
HEADER_NAME = 'X-XSRF-TOKEN'


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Cookie to Header')
        callbacks.registerHttpListener(self)

        return

    def _processCookies(self, cookieString):
        for cookie in cookieString.split(';'):
            cookie = cookie.strip(' ')
            if cookie.startswith(COOKIE_NAME):
                return cookie.split('=')[1]

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        if messageIsRequest:
            requestInfo = self._helpers.analyzeRequest(currentMessage)
            headers = requestInfo.getHeaders()
            msgBody = currentMessage.getRequest()[requestInfo.getBodyOffset():]

            # Add cookie as header
            cval = ''

            for header in headers[:]:
                # Remove the header if it exists. We only want one header.
                if header.startswith(HEADER_NAME):
                    headers.remove(header)

                # Get the cookie value if it exists.
                if header.startswith('Cookie: '):
                    cval = self._processCookies(header[8:])

            # Add custom header
            headers.add('{0}: {1}'.format(HEADER_NAME, cval))

            # Build new message with the new header
            message = self._helpers.buildHttpMessage(headers, msgBody)

            # Print headers to UI. Enable this if needed.
            # print '\r\n'.join(headers)
            # print

            # Update request with new headers
            currentMessage.setRequest(message)

        return
