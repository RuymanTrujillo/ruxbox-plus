// Pure policy compiler. No router I/O, application plan, or normalization.
// Numeric masks target the reconstructed ASUS model, not a verified Livebox grammar.
export const POLICY_LIMITS = Object.freeze({blocks: 100, exceptions: 100, samples: 200, boxes: 4096, work: 250000, exactExpansion: 100});
const ALL = 1023, MAX_WIDTH = 32;
const digits = value => typeof value === 'string' && value.length >= 1 && value.length <= MAX_WIDTH && !/[^0-9]/.test(value);
const own = (value, key) => Object.hasOwn(value, key);
const popcount = mask => { let n = 0; for (; mask; mask &= mask - 1) n++; return n; };
const boxCount = box => box.reduce((count, mask) => count * BigInt(popcount(mask)), 1n);
const countAll = boxes => boxes.reduce((count, box) => count + boxCount(box), 0n);
const lex = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const compareBox = (a, b) => a.length - b.length || lex(a.join(','), b.join(','));
const exactBox = value => [...value].map(digit => 1 << Number(digit));
const contains = (box, value) => box.length === value.length && [...value].every((digit, index) => (box[index] & (1 << Number(digit))) !== 0);
function fail(code) { throw Object.assign(new Error(code), {name: 'PolicyError', code}); }
function shape(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(key => !own(value, key))) fail(code);
}
function budget() {
  let work = 0;
  return {
    step(amount = 1) { work += amount; if (work > POLICY_LIMITS.work) fail('POLICY_COMPLEXITY_LIMIT'); },
    size(length) { if (length > POLICY_LIMITS.boxes) fail('POLICY_COMPLEXITY_LIMIT'); },
  };
}

/** Fixed width only: digits, x/X, and numeric classes with ascending ranges. */
function parseMask(value) {
  if (typeof value !== 'string' || !value.length || value.length > 512) fail('INVALID_BLOCK');
  const box = [];
  for (let i = 0; i < value.length;) {
    const character = value[i++];
    if (character >= '0' && character <= '9') box.push(1 << Number(character));
    else if (character === 'x' || character === 'X') box.push(ALL);
    else if (character === '[') {
      let mask = 0, closed = false;
      while (i < value.length) {
        if (value[i] === ']') { i++; closed = true; break; }
        const start = value[i++];
        if (!(start >= '0' && start <= '9')) fail('INVALID_BLOCK');
        if (value[i] === '-') {
          i++; const end = value[i++];
          if (!(end >= '0' && end <= '9') || end <= start) fail('INVALID_BLOCK');
          for (let digit = Number(start); digit <= Number(end); digit++) mask |= 1 << digit;
        } else mask |= 1 << Number(start);
      }
      if (!closed || mask === 0) fail('INVALID_BLOCK');
      box.push(mask);
    } else fail('INVALID_BLOCK');
    if (box.length > MAX_WIDTH) fail('INVALID_BLOCK');
  }
  if (!box.length) fail('INVALID_BLOCK');
  return box;
}

// Inclusive, equal-width decimal interval. At most O(width * 10) aligned boxes;
// the interval's individual values are never enumerated.
function rangeBoxes(from, to, guard) {
  const width = from.length, end = BigInt(to), powers = [1n];
  for (let i = 1; i <= width; i++) powers.push(powers[i - 1] * 10n);
  const boxes = [];
  for (let current = BigInt(from); current <= end;) {
    let suffix = 0;
    while (suffix < width && current % powers[suffix + 1] === 0n && current + powers[suffix + 1] - 1n <= end) { suffix++; guard.step(); }
    const text = current.toString().padStart(width, '0');
    boxes.push([...exactBox(text.slice(0, width - suffix)), ...Array(suffix).fill(ALL)]);
    current += powers[suffix]; guard.step(); guard.size(boxes.length);
  }
  return boxes;
}

/** Disjoint boxes for A minus B, with at most width fragments. */
function subtract(a, b, guard) {
  guard.step();
  if (a.length !== b.length) return [a];
  const intersection = [];
  for (let i = 0; i < a.length; i++) {
    guard.step(); const common = a[i] & b[i];
    if (!common) return [a];
    intersection.push(common);
  }
  const remainder = a.slice(), pieces = [];
  for (let i = 0; i < a.length; i++) {
    const outside = remainder[i] & (ALL ^ b[i]);
    if (outside) { const piece = remainder.slice(); piece[i] = outside; pieces.push(piece); }
    remainder[i] = intersection[i];
  }
  return pieces;
}
function unite(raw, guard) {
  const boxes = [];
  // Broad boxes first reduces intermediate splits; ordering is input-order independent.
  raw.sort((a, b) => a.length - b.length || (boxCount(a) > boxCount(b) ? -1 : boxCount(a) < boxCount(b) ? 1 : compareBox(a, b)));
  for (const next of raw) {
    let pieces = [next];
    for (const previous of boxes) {
      const remaining = [];
      for (const piece of pieces) { remaining.push(...subtract(piece, previous, guard)); guard.size(remaining.length); }
      pieces = remaining; if (!pieces.length) break;
    }
    boxes.push(...pieces); guard.size(boxes.length);
  }
  return boxes;
}
function compact(input, guard) {
  let boxes = input.map(box => box.slice()), changed;
  do {
    changed = false;
    for (let axis = 0; axis < MAX_WIDTH; axis++) {
      const groups = new Map(), untouched = [];
      for (const box of boxes) {
        guard.step();
        if (axis >= box.length) { untouched.push(box); continue; }
        const key = `${box.length}:` + box.map((mask, index) => index === axis ? '_' : mask).join(',');
        if (groups.has(key)) { groups.get(key)[axis] |= box[axis]; changed = true; }
        else groups.set(key, box.slice());
      }
      boxes = [...untouched, ...groups.values()];
    }
  } while (changed);
  return boxes.sort(compareBox);
}
function token(mask) {
  if (mask === ALL) return 'X';
  const choices = Array.from({length: 10}, (_, digit) => digit).filter(digit => mask & (1 << digit));
  if (choices.length === 1) return String(choices[0]);
  let result = '';
  for (let i = 0; i < choices.length;) {
    let j = i; while (j + 1 < choices.length && choices[j + 1] === choices[j] + 1) j++;
    result += j - i >= 2 ? `${choices[i]}-${choices[j]}` : choices.slice(i, j + 1).join(''); i = j + 1;
  }
  return '[' + result + ']';
}
function expand(boxes, count, guard) {
  if (count > BigInt(POLICY_LIMITS.exactExpansion)) return null;
  const values = [];
  function walk(box, index, value) {
    guard.step();
    if (index === box.length) { values.push(value); return; }
    for (let digit = 0; digit < 10; digit++) if (box[index] & (1 << digit)) walk(box, index + 1, value + digit);
  }
  for (const box of boxes) walk(box, 0, '');
  return values.sort((a, b) => a.length - b.length || lex(a, b));
}

export function compilePolicy(policy, options = {}) {
  shape(policy, ['blocks', 'exceptions', 'samples'], 'INVALID_POLICY');
  if (!Array.isArray(policy.blocks) || policy.blocks.length > POLICY_LIMITS.blocks ||
      !Array.isArray(policy.exceptions) || policy.exceptions.length > POLICY_LIMITS.exceptions ||
      !Array.isArray(policy.samples) || policy.samples.length > POLICY_LIMITS.samples ||
      policy.samples.some(value => typeof value !== 'string' || value.length > 256)) fail('INVALID_POLICY');
  if (policy.exceptions.some(value => !digits(value))) fail('INVALID_EXCEPTION');
  if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(key => !['incoming', 'capacity', 'outgoingCount', 'enabledProfiles'].includes(key))) fail('INVALID_CURRENT_STATE');
  const incoming = options.incoming ?? [], capacity = options.capacity ?? 100;
  const enabledProfiles = options.enabledProfiles ?? 0, outgoingCount = options.outgoingCount ?? 0;
  if (!Array.isArray(incoming) || incoming.length > 100 || !Number.isInteger(capacity) || capacity < 0 || capacity > 100 ||
      !Number.isInteger(enabledProfiles) || enabledProfiles < 0 || enabledProfiles > 10 ||
      !Number.isInteger(outgoingCount) || outgoingCount < 0 || outgoingCount > 100 ||
      incoming.some(rule => !rule || typeof rule.id !== 'string' || !/^(?:0|[1-9][0-9]{0,9})$/.test(rule.id) || /[^0-9]/.test(rule.id) ||
        BigInt(rule.id) > 2147483647n || typeof rule.pattern !== 'string' || !rule.pattern.length || rule.pattern.length > 2048) ||
      new Set(incoming.map(rule => rule.id)).size !== incoming.length) fail('INVALID_CURRENT_STATE');
  const guard = budget(), raw = [];
  for (const block of policy.blocks) {
    const kinds = {exact: ['kind', 'value'], prefix: ['kind', 'value', 'length'], range: ['kind', 'from', 'to'], pattern: ['kind', 'value']};
    if (typeof block?.kind !== 'string' || !own(kinds, block.kind)) fail('INVALID_BLOCK');
    shape(block, kinds[block.kind], 'INVALID_BLOCK');
    if (block.kind === 'pattern') raw.push(parseMask(block.value));
    else if (block.kind === 'range') {
      if (!digits(block.from) || !digits(block.to) || block.from.length !== block.to.length || block.from > block.to) fail('INVALID_BLOCK');
      raw.push(...rangeBoxes(block.from, block.to, guard));
    } else {
      if (!digits(block.value)) fail('INVALID_BLOCK');
      if (block.kind === 'prefix' && (!Number.isInteger(block.length) || block.length < block.value.length || block.length > MAX_WIDTH)) fail('INVALID_BLOCK');
      raw.push([...exactBox(block.value), ...Array(block.kind === 'prefix' ? block.length - block.value.length : 0).fill(ALL)]);
    }
    guard.size(raw.length);
  }
  let boxes = unite(raw, guard);
  const unionCount = countAll(boxes), exceptions = [...new Set(policy.exceptions)].sort((a, b) => a.length - b.length || lex(a, b));
  const unmatched = [];
  for (const exception of exceptions) {
    if (!boxes.some(box => contains(box, exception))) unmatched.push(exception);
    const point = exactBox(exception), remaining = [];
    for (const box of boxes) { remaining.push(...subtract(box, point, guard)); guard.size(remaining.length); }
    boxes = remaining;
  }
  boxes = compact(boxes, guard);
  const count = countAll(boxes), referenceMasks = boxes.map(box => box.map(token).join(''));
  const exactExpansion = expand(boxes, count, guard), exceptionSet = new Set(exceptions);
  const current = incoming.map(rule => {
    if (digits(rule.pattern)) return {...rule, literal: true, box: exactBox(rule.pattern)};
    try { return {...rule, literal: false, box: parseMask(rule.pattern)}; }
    catch { return {...rule, literal: false, box: null}; }
  });
  const conflicts = [], unknownExisting = current.filter(rule => !rule.literal).map(rule => ({ruleId: rule.id, pattern: rule.pattern,
    reason: rule.box ? 'REFERENCE_PATTERN_UNVERIFIED' : 'UNSUPPORTED_EXISTING_PATTERN'}));
  for (const exception of exceptions) for (const rule of current) if (rule.box && contains(rule.box, exception)) {
    conflicts.push({exception, ruleId: rule.id, pattern: rule.pattern, certainty: rule.literal ? 'exact' : 'reference'});
  }
  const samples = policy.samples.map(value => {
    if (!digits(value)) return {value, supported: false, policyDecision: 'unknown', decision: 'unknown', reason: 'UNSUPPORTED_IDENTIFIER_NO_NORMALIZATION'};
    const blocked = boxes.some(box => contains(box, value));
    const policyDecision = blocked ? 'blocked' : exceptionSet.has(value) ? 'exception' : 'unmatched';
    if (current.some(rule => rule.literal && rule.pattern === value)) return {value, supported: true, policyDecision, decision: 'blocked', reason: 'EXISTING_EXACT_RULE'};
    if (blocked) return {value, supported: true, policyDecision, decision: 'blocked', reason: 'REQUESTED_POLICY_MODEL'};
    if (unknownExisting.length || enabledProfiles) return {value, supported: true, policyDecision, decision: 'unknown', reason: enabledProfiles ? 'ACTIVE_PROFILES_NOT_MODELED' : 'EXISTING_PATTERN_NOT_VERIFIED'};
    return {value, supported: true, policyDecision, decision: 'allowed', reason: 'POLICY_MODEL_ONLY'};
  });
  const existingExact = new Set(current.filter(rule => rule.literal).map(rule => rule.pattern));
  const additionalExactCount = exactExpansion === null ? null : exactExpansion.filter(value => !existingExact.has(value)).length;
  const available = Math.max(0, capacity - incoming.length);
  return {model: 'ASUS_REFERENCE_UNVERIFIED_ON_LIVEBOX', referenceUnverified: true, nativePatternsWritable: false, normalization: 'none',
    count: count.toString(), referenceMasks, exactExpansion,
    capacity: {limit: capacity, existingCount: incoming.length, available, referenceMaskCount: referenceMasks.length,
      referenceMaskFits: incoming.length + referenceMasks.length <= capacity, additionalExactCount,
      exactExpansionFits: additionalExactCount === null ? null : incoming.length + additionalExactCount <= capacity},
    exceptions: {requestedCount: policy.exceptions.length, uniqueCount: exceptions.length, excludedCount: (unionCount - count).toString(), unmatched},
    conflicts, unknownExisting, samples, existingConfiguration: {outgoingCount, enabledProfiles},
  };
}
export const previewPolicy = compilePolicy;
