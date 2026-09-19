---
'@platform-sec/sensitive-string-core': minor
---

Add the `url` mask strategy: keep the scheme, host, port and path of a URL, and hide the userinfo,
every query value and the fragment.

```ts
new SensitiveString('https://x-access-token:ghp_abcdef123456@github.com/org/repo.git', 'sensitive').mask({
  strategy: 'url',
});
// 'https://***@github.com/org/repo.git'
```

Two corpus records wanted this rendering and could not get it: a clone message should keep which
repository it names, and a custom policy cannot do it because `validateRedactFunction` refuses a
`redact` that is the identity on its non-URL canaries. The hidden parts are written at a fixed width
so the rendering does not disclose a credential's length, and the rendering is the parsed URL written
back, so it is normalized. The floor applies as to every strategy: a URL with nothing to hide hides
nothing and redacts in full, which is deliberate. A caller who marked a URL sensitive and wants its
bare form shown has marked the wrong thing; wrap the credential and keep the URL.
