.class public Lcom/example/web/SecureWebViewClient;
.super Landroid/webkit/WebViewClient;

.method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
    .locals 0

    invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
    return-void
.end method
