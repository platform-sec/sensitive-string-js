/**
 * Direct coverage for the shared AST layer.
 *
 * Most of this module is exercised through the rule suites, which is the right
 * place for it. What is left are the paths a real parser never takes: the
 * traversal fallback for a parser that publishes no visitor keys, the
 * defensive reads for a malformed node, and the two compatibility shims, each
 * of which only one ESLint major ever exercises. Those are the paths that break
 * quietly on somebody else's setup, so they are driven here with synthetic
 * nodes.
 */
import { describe, it, expect } from 'vitest';
import {
  asMethodCall,
  calleeChainNames,
  childNodes,
  findMethodCalls,
  getAncestors,
  getSourceCode,
  staticKeyName,
  staticPropertyName,
  unwrap,
} from './ast.js';
import type { AstNode, RuleContext, SourceCode } from './types.js';

/** A node built from a plain object, which is all any of these functions need. */
function node(shape: Record<string, unknown>): AstNode {
  return shape as unknown as AstNode;
}

describe('unwrap', () => {
  it('strips nested wrappers down to the expression', () => {
    const inner = node({ type: 'Identifier', name: 'x' });
    const wrapped = node({
      type: 'TSAsExpression',
      expression: node({ type: 'ChainExpression', expression: inner }),
    });

    expect(unwrap(wrapped)).toBe(inner);
  });

  it('is idempotent', () => {
    const inner = node({ type: 'Identifier', name: 'x' });
    expect(unwrap(unwrap(node({ type: 'ChainExpression', expression: inner })))).toBe(inner);
  });

  it('stops at a wrapper with nothing inside rather than looping', () => {
    const empty = node({ type: 'TSNonNullExpression' });
    expect(unwrap(empty)).toBe(empty);
  });
});

describe('staticPropertyName', () => {
  const property = node({ type: 'Identifier', name: 'reveal' });

  it('reads a plain property', () => {
    expect(staticPropertyName(node({ type: 'MemberExpression', computed: false, property }))).toBe(
      'reveal'
    );
  });

  it('reads a computed string key', () => {
    const key = node({ type: 'Literal', value: 'reveal' });
    expect(
      staticPropertyName(node({ type: 'MemberExpression', computed: true, property: key }))
    ).toBe('reveal');
  });

  it('refuses to guess at a computed identifier', () => {
    const key = node({ type: 'Identifier', name: 'method' });
    expect(
      staticPropertyName(node({ type: 'MemberExpression', computed: true, property: key }))
    ).toBeUndefined();
  });

  it('refuses to guess at a non-string literal key', () => {
    const key = node({ type: 'Literal', value: 0 });
    expect(
      staticPropertyName(node({ type: 'MemberExpression', computed: true, property: key }))
    ).toBeUndefined();
  });

  it('yields nothing for a node with no property', () => {
    expect(staticPropertyName(node({ type: 'Identifier', name: 'x' }))).toBeUndefined();
  });
});

describe('staticKeyName', () => {
  it('reads a quoted key', () => {
    const key = node({ type: 'Literal', value: 'reason' });
    expect(staticKeyName(node({ type: 'Property', computed: false, key }))).toBe('reason');
  });

  it('yields nothing for a node with no key', () => {
    expect(staticKeyName(node({ type: 'SpreadElement' }))).toBeUndefined();
  });
});

describe('asMethodCall', () => {
  it('yields nothing for a bare call', () => {
    expect(
      asMethodCall(
        node({
          type: 'CallExpression',
          callee: node({ type: 'Identifier', name: 'f' }),
          arguments: [],
        })
      )
    ).toBeUndefined();
  });

  it('yields nothing for a call with no callee', () => {
    expect(asMethodCall(node({ type: 'CallExpression', arguments: [] }))).toBeUndefined();
  });

  it('yields nothing for a call whose method name is not knowable', () => {
    const callee = node({
      type: 'MemberExpression',
      computed: true,
      object: node({ type: 'Identifier', name: 'x' }),
      property: node({ type: 'Identifier', name: 'method' }),
    });

    expect(asMethodCall(node({ type: 'CallExpression', callee, arguments: [] }))).toBeUndefined();
  });
});

describe('calleeChainNames', () => {
  it('steps over an index rather than stopping at it', () => {
    // `arr[i].info` cannot name the middle link, but the object behind it is
    // still reachable, so a rule matching on `arr` is not defeated by the index.
    const callee = node({
      type: 'MemberExpression',
      computed: false,
      property: node({ type: 'Identifier', name: 'info' }),
      object: node({
        type: 'MemberExpression',
        computed: true,
        property: node({ type: 'Identifier', name: 'i' }),
        object: node({ type: 'Identifier', name: 'arr' }),
      }),
    });

    expect(calleeChainNames(callee)).toEqual(['info', 'arr']);
  });

  it('stops at `this` without inventing a name', () => {
    const callee = node({
      type: 'MemberExpression',
      computed: false,
      property: node({ type: 'Identifier', name: 'info' }),
      object: node({ type: 'ThisExpression' }),
    });

    expect(calleeChainNames(callee)).toEqual(['info']);
  });
});

describe('childNodes', () => {
  const parent = node({ type: 'Program' });
  const child = node({ type: 'Identifier', name: 'x' });
  const subject = node({
    type: 'ExpressionStatement',
    expression: child,
    extra: [child, 'not a node', null],
    parent,
    range: [0, 1],
  });

  it("follows the parser's visitor keys when there are any", () => {
    expect(childNodes(subject, { ExpressionStatement: ['expression'] })).toEqual([child]);
  });

  it("falls back to the node's own fields when there are none", () => {
    const found = childNodes(subject, undefined);

    expect(found).toContain(child);
    // Following `parent` would walk back up the tree and never terminate.
    expect(found).not.toContain(parent);
  });

  it('enumerates rather than prunes a node type the keys do not describe', () => {
    // A map that says nothing about this node type must not stop the search
    // inside it; a pruned subtree is a missed leak.
    expect(childNodes(subject, { Program: [] })).toContain(child);
  });
});

describe('findMethodCalls', () => {
  /** `a.reveal(b.reveal())`, built by hand. */
  function revealCall(receiver: string, args: readonly AstNode[]): AstNode {
    return node({
      type: 'CallExpression',
      callee: node({
        type: 'MemberExpression',
        computed: false,
        object: node({ type: 'Identifier', name: receiver }),
        property: node({ type: 'Identifier', name: 'reveal' }),
      }),
      arguments: args,
    });
  }

  it('finds a match nested inside another match', () => {
    const inner = revealCall('b', []);
    const outer = revealCall('a', [inner]);

    const found = findMethodCalls(outer, new Set(['reveal']), undefined);

    expect(found).toHaveLength(2);
    expect(found[0]).toBe(outer);
    expect(found[1]).toBe(inner);
  });

  it('returns matches in source order', () => {
    const first = revealCall('a', []);
    const second = revealCall('b', []);
    const array = node({ type: 'ArrayExpression', elements: [first, second] });

    expect(findMethodCalls(array, new Set(['reveal']), undefined)).toEqual([first, second]);
  });
});

describe('ESLint compatibility shims', () => {
  const target = node({ type: 'Identifier', name: 'x' });
  const ancestors = [node({ type: 'Program' })];
  const sourceCode = { visitorKeys: {} } as unknown as SourceCode;

  it('prefers the ESLint 9 source code property', () => {
    const context = { options: [], sourceCode, report: () => {} } as unknown as RuleContext;
    expect(getSourceCode(context)).toBe(sourceCode);
  });

  it('falls back to the ESLint 8 source code getter', () => {
    const context = {
      options: [],
      getSourceCode: () => sourceCode,
      report: () => {},
    } as unknown as RuleContext;

    expect(getSourceCode(context)).toBe(sourceCode);
  });

  it('yields nothing when neither is present', () => {
    expect(
      getSourceCode({ options: [], report: () => {} } as unknown as RuleContext)
    ).toBeUndefined();
  });

  it('prefers the ESLint 9 ancestors call, which does not warn', () => {
    const context = {
      options: [],
      sourceCode: { ...sourceCode, getAncestors: () => ancestors },
      getAncestors: () => {
        throw new Error('the deprecated call must not be reached');
      },
      report: () => {},
    } as unknown as RuleContext;

    expect(getAncestors(context, target)).toBe(ancestors);
  });

  it('falls back to the ESLint 8 ancestors call', () => {
    const context = {
      options: [],
      sourceCode,
      getAncestors: () => ancestors,
      report: () => {},
    } as unknown as RuleContext;

    expect(getAncestors(context, target)).toBe(ancestors);
  });

  it('yields an empty list when neither is present', () => {
    expect(
      getAncestors({ options: [], report: () => {} } as unknown as RuleContext, target)
    ).toEqual([]);
  });
});
