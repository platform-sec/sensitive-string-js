import { describe, it, expect } from 'vitest';
import { DOCS_BASE_URL, ruleDocs } from './docs.js';
import { rules } from './index.js';

describe('ruleDocs', () => {
  it('omits the url when there is no honest one to give', () => {
    // `exactOptionalPropertyTypes` distinguishes an absent key from one set to
    // `undefined`, and ESLint's config inspector renders the second as a broken
    // link. The key has to be absent.
    expect(ruleDocs('no-log-reveal', 'description', true, undefined)).not.toHaveProperty('url');
  });

  it('builds a url per rule once a base is set', () => {
    expect(ruleDocs('no-log-reveal', 'description', true, 'https://example.test/rules/')).toEqual({
      description: 'description',
      recommended: true,
      url: 'https://example.test/rules/no-log-reveal.md',
    });
  });

  it('leaves every shipped rule without a url while the base is unset', () => {
    // This assertion is expected to be inverted the day the project has a home:
    // set DOCS_BASE_URL, and every rule picks the link up at once.
    expect(DOCS_BASE_URL).toBeUndefined();
    for (const rule of Object.values(rules)) {
      expect(rule.meta.docs).not.toHaveProperty('url');
    }
  });
});
