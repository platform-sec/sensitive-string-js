---
'@platform-sec/sensitive-string-core': minor
---

Add `wrapSensitiveByClassification()` and `checkClassifiedFieldsWrapped()`: bulk wrapping for a
bag whose keys the caller does not choose.

```ts
// Keep two headers readable, wrap every other one, named or not.
const headers = wrapSensitiveByClassification(req.headers, {
  fields: { referer: 'plain', host: 'plain' },
  fallback: 'sensitive',
});

// A plugin's return value: everything it hands back is a credential.
const creds = wrapSensitiveByClassification(await plugin.getCredentials(), { fallback: 'credential' });
```

`wrapSensitiveByPath` takes an enumerated list of the paths that are sensitive, which is the right
entry when the payload's shape is known and the wrong one for a header bag, a `.env` file, a plugin
loaded at run time or a provider credential object whose keys are data: a path list over such a bag
is a denylist turned inside out, and the key nobody named arrives unwrapped, silently. The new entry
takes the classification spec the secrets and env layers already use, `fields`, then `rules`, then
`fallback`, and a `fallback` inverts the default so the list a caller maintains is the short one.

Strings only are wrapped; a number, a boolean and `null` keep their type. Every element of an array
of strings is wrapped under the array's own name, as the path helper now does at a declared path. An
already wrapped value is kept, and a protected value handed in as the whole object is refused with a
`TypeError` by both wrappers rather than walked in place. `constructor`, `prototype` and an own
`__proto__` are classified like any other key, since a payload chooses its keys and a header named
`constructor` is legal; the write keeps `__proto__` an own data property. A label may be a fixed
string or a function of the leaf's path and key, never its value, and construction options apply to
every wrapped leaf.

`checkClassifiedFieldsWrapped(obj, spec)` walks the object and asks the spec, which is the direction
`checkSensitiveFieldsWrapped` cannot look in: that one walks the config and asks the object, so a key
the object carries and the config never named is invisible to it.

`wrapSensitiveByPath` now wraps every string element of an array at a declared path too, through
nested arrays, with the class, label and options the path declares. Declaring
`'db.replicaUrls': 'credential'` over a list of connection strings used to wrap nothing, silently,
and the two report functions vouched for it; the report side was fixed first, and this closes the
gap itself. It is a behaviour change for a configuration that declares a list and relied on it
passing through: the elements arrive wrapped, which is loud. `unwrapSensitiveByPath` reveals every
instance in such a list, `validateSensitiveFieldConfig` accepts a list of strings and still reports
an object, a number, or a list holding either as unwrappable, and `checkSensitiveFieldsWrapped`
reports a list once, under its path, if anything in it is not an instance.
