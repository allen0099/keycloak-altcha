<#-- Test-only page: just enough markup for src/it/e2e.py, no styling, no widget. -->
<!DOCTYPE html>
<html>
<body>
<#if message?has_content><p id="message" class="${message.type}">${kcSanitize(message.summary)?no_esc}</p></#if>
<form id="kc-reset-password-form" action="${url.loginAction}" method="post">
  <input name="username" value="${(auth.attemptedUsername)!''}">
  <button type="submit">Submit</button>
</form>
<pre id="altcha-challenge">${altchaChallenge!""}</pre>
</body>
</html>
