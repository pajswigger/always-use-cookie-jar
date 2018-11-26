package burp


class BurpExtender: IBurpExtender {
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        callbacks.setExtensionName("Always use cookie jar")
        callbacks.registerHttpListener(HttpListener(callbacks))
    }
}


class HttpListener(val callbacks: IBurpExtenderCallbacks): IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        if (!messageIsRequest) {
            return
        }
        if (toolFlag == 4) { // IBurpExtenderCallbacks.TOOL_PROXY
            return
        }

        val requestInfo = callbacks.helpers.analyzeRequest(messageInfo.httpService, messageInfo.request)
        val host = requestInfo.url.host
        val cookies = callbacks.cookieJarContents.filter { it.domain == host }.map { "${it.name}=${it.value}" }

        val headers = requestInfo.headers.filter { !it.startsWith("Cookie:") }. toMutableList()
        headers.add("Cookie: " + cookies.joinToString("; "))

        messageInfo.request = callbacks.helpers.buildHttpMessage(headers, messageInfo.request.copyOfRange(requestInfo.bodyOffset, messageInfo.request.size))
    }
}
