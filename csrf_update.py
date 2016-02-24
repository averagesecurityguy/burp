from burp import IBurpExtender
from burp import IHttpListener

import re

#
# I was testing a web app where each response contained a new CSRF token and
# the next request had to include that token or else the user would be logged
# out of the application. For each tool except the Proxy, this extension looks
# at the last response, extracts the current token from the response, and
# copies it into the current request.
# 
# Because of this CSRF token handling I had to scan the server with one
# thread because if I used more than one thread the CSRF tokens would get out
# of sync and I would get logged out.
#

csrf_re = re.compile(r'name="csrfToken"\s+value="(.*?)" />')

 
class BurpExtender(IBurpExtender, IHttpListener):
    csrf = ''

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CSRF Extract and Send")
        callbacks.registerHttpListener(self)

        return

    def getBody(self, rawMessage, parsedMessage):
        return self._helpers.bytesToString(rawMessage[parsedMessage.getBodyOffset():])

    def toString(self, byteArray):
        return self._helpers.bytesToString(byteArray)

    def parseResponse(self, currentMessage):
        response = currentMessage.getResponse()
        parsedResponse = self._helpers.analyzeResponse(response)
        respBody = self.getBody(response, parsedResponse)        

        # Extract the CSRF token from the body
        m = csrf_re.search(respBody)
        if m is not None:
            BurpExtender.csrf = m.group(1)

    def parseRequest(self, currentMessage):
        request = currentMessage.getRequest()
        parsedRequest = self._helpers.analyzeRequest(request)
        reqBody = self.getBody(request, parsedRequest)

        # print('\nOriginal Request:\n{0}'.format(self.toString(request)))

        # Update the CSRF token in the body.
        if BurpExtender.csrf != '':
            newBody = re.sub(r'csrfToken=.*?&', 'csrfToken={0}&'.format(BurpExtender.csrf), reqBody)
        else:
            newBody = reqBody

        # Build new request
        newRequest = self._helpers.buildHttpMessage(parsedRequest.getHeaders(), newBody)
        # print('Modified Request:\n{0}'.format(self.toString(newRequest)))
        
        currentMessage.setRequest(newRequest)


    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        if toolFlag != self._callbacks.TOOL_PROXY:
            if messageIsRequest:
                self.parseRequest(currentMessage)
            else:
                self.parseResponse(currentMessage)
