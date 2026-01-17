using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace WebPush.Model;

public class WebPushException(string message, PushSubscription pushSubscription, HttpResponseMessage responseMessage) : Exception(message)
{
    public HttpStatusCode StatusCode => HttpResponseMessage.StatusCode;

    public HttpResponseHeaders Headers => HttpResponseMessage.Headers;
    public PushSubscription PushSubscription { get; set; } = pushSubscription;
    public HttpResponseMessage HttpResponseMessage { get; set; } = responseMessage;
}