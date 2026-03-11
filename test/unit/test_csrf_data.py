"""Reusable test data for CSRF plugin tests."""

HTML_WITH_CSRF_TOKEN = '''
<html>
  <body>
    <form action="/submit" method="post">
      <input type="hidden" name="csrf_token" value="abc123" />
      <input type="text" name="username" />
    </form>
  </body>
</html>
'''

HTML_WITHOUT_CSRF = '''
<html>
  <body>
    <form action="/login" method="post">
      <input type="text" name="username" />
      <input type="password" name="password" />
    </form>
  </body>
</html>
'''

HTML_NO_FORMS = '<html><head></head><body><p>No forms here</p></body></html>'

HTML_WITH_STATIC_TOKEN = '''
<html>
  <body>
    <form action="/submit" method="post">
      <input type="hidden" name="csrf_token" value="STATIC_VALUE_123" />
      <input type="text" name="username" />
    </form>
  </body>
</html>
'''

HTML_GET_FORM_NO_TOKEN = '''
<html>
  <body>
    <form action="/search" method="get">
      <input type="text" name="q" />
    </form>
  </body>
</html>
'''

HTML_MIXED_FORMS = '''
<html>
  <body>
    <form action="/submit" method="post">
      <input type="hidden" name="csrf_token" value="unique_abc" />
      <input type="text" name="data" />
    </form>
    <form action="/search" method="get">
      <input type="text" name="q" />
    </form>
  </body>
</html>
'''

# L5: Meta tag CSRF token
HTML_WITH_META_TOKEN = '''
<html>
  <head>
    <meta name="csrf-token" content="meta_token_abc123" />
  </head>
  <body><p>Page with meta token</p></body>
</html>
'''

HTML_WITH_META_TOKEN_STATIC = '''
<html>
  <head>
    <meta name="csrf-token" content="STATIC_META_VALUE" />
  </head>
  <body><p>Page with static meta token</p></body>
</html>
'''

HTML_WITH_META_TOKEN_EMPTY = '''
<html>
  <head>
    <meta name="csrf-token" content="" />
  </head>
  <body><p>Page with empty meta token</p></body>
</html>
'''

# L6: JS global variable token
HTML_WITH_JS_TOKEN = '''
<html>
  <body>
    <script>
      var csrfToken = "js_dynamic_token_abc";
    </script>
  </body>
</html>
'''

HTML_WITH_JS_TOKEN_STATIC = '''
<html>
  <body>
    <script>
      window.csrf_token = "STATIC_JS_VALUE_12345678";
    </script>
  </body>
</html>
'''
