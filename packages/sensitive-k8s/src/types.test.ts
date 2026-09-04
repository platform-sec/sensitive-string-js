import { describe, it, expect } from 'vitest';
import { compileClassification } from '@platform-sec/sensitive-string-core';

import { K8S_SECRET_TYPES, isKnownSecretType, k8sSecretTypeSpec } from './types.js';

describe('k8sSecretTypeSpec', () => {
  it('keeps a certificate plain, which is the case these specs exist for', () => {
    const spec = k8sSecretTypeSpec('kubernetes.io/tls');
    const compiled = compileClassification({ ...spec });

    expect(compiled.classify('tls.crt')).toBe('plain');
    expect(compiled.classify('ca.crt')).toBe('plain');
    expect(compiled.classify('tls.key')).toBe('credential');
  });

  it('classifies a basic-auth username as sensitive rather than as a credential', () => {
    const compiled = compileClassification({ ...k8sSecretTypeSpec('kubernetes.io/basic-auth') });

    expect(compiled.classify('username')).toBe('sensitive');
    expect(compiled.classify('password')).toBe('credential');
  });

  it('keeps an ssh public key plain and the private key a credential', () => {
    const compiled = compileClassification({ ...k8sSecretTypeSpec('kubernetes.io/ssh-auth') });

    expect(compiled.classify('ssh-privatekey')).toBe('credential');
    expect(compiled.classify('ssh-publickey')).toBe('plain');
  });

  it('keeps a service account token secret ca.crt and namespace plain', () => {
    const compiled = compileClassification({
      ...k8sSecretTypeSpec('kubernetes.io/service-account-token'),
    });

    expect(compiled.classify('token')).toBe('credential');
    expect(compiled.classify('ca.crt')).toBe('plain');
    expect(compiled.classify('namespace')).toBe('plain');
  });

  it('classifies an expanded pull secret by leaf key, not by dot path', () => {
    // A registry hostname contains dots, so a rule written against the path
    // would have to anticipate `auths.index.docker.io.auth`.
    const compiled = compileClassification({
      ...k8sSecretTypeSpec('kubernetes.io/dockerconfigjson'),
    });

    expect(compiled.classify('auths.index.docker.io.auth', ['auth'])).toBe('credential');
    expect(compiled.classify('auths.index.docker.io.password', ['password'])).toBe('credential');
    expect(compiled.classify('auths.index.docker.io.username', ['username'])).toBe('sensitive');
  });

  it('classifies an unexpanded pull secret as one credential', () => {
    const compiled = compileClassification({
      ...k8sSecretTypeSpec('kubernetes.io/dockerconfigjson'),
    });

    expect(compiled.classify('.dockerconfigjson')).toBe('credential');
  });

  it('gives an Opaque secret no field rules and a closed fallback', () => {
    const spec = k8sSecretTypeSpec('Opaque');

    expect(spec.fields).toBeUndefined();
    expect(spec.fallback).toBe('credential');
  });

  it('returns a fresh object each time, so a caller cannot mutate the table', () => {
    const first = k8sSecretTypeSpec('kubernetes.io/tls');
    const second = k8sSecretTypeSpec('kubernetes.io/tls');

    expect(first).not.toBe(second);
    expect(first.fields).not.toBe(second.fields);
  });

  it('defaults every type to credential for keys it does not name', () => {
    for (const type of K8S_SECRET_TYPES) {
      expect(k8sSecretTypeSpec(type).fallback).toBe('credential');
    }
  });
});

describe('isKnownSecretType', () => {
  it('recognizes the well-known types', () => {
    expect(isKnownSecretType('kubernetes.io/tls')).toBe(true);
  });

  it('does not recognize a custom type', () => {
    expect(isKnownSecretType('example.com/my-type')).toBe(false);
    expect(isKnownSecretType(undefined)).toBe(false);
  });
});
