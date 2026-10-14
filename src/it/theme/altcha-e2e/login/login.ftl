<#-- Test-only page: just enough markup for src/it/e2e.py, no styling, no widget. -->
<!DOCTYPE html>
<html>
<body>
<#if message?has_content><p id="message" class="${message.type}">${kcSanitize(message.summary)?no_esc}</p></#if>
<form id="kc-form-login" action="${url.loginAction}" method="post">
  <input name="username" value="${(login.username)!''}">
  <input name="password" type="password">
  <button type="submit">Sign in</button>
</form>
<pre id="altcha-challenge">${altchaChallenge!""}</pre>
<a id="reset-password" href="${url.loginResetCredentialsUrl}">Forgot password</a>
</body>
</html>
