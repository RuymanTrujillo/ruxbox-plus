import {createHash} from 'node:crypto';

export const MAX_ENTRIES = 100;
export const MAX_EXACT_PATTERN_LENGTH = 32; // Manager implementation bound, not a firmware grammar claim.
export const MAX_EXISTING_PATTERN_LENGTH = 4096; // UTF-16 code units; deletion identity only, never a creation grammar.

const profileKinds = ['enable', 'direction', 'name', 'rule'];
const names = ['incoming_entry_num', 'outgoing_entry_num'];
for (const direction of ['incoming', 'outgoing']) {
  for (let i = 0; i < MAX_ENTRIES; i++) names.push(`${direction}_entry_str_${i}`);
}
for (const kind of profileKinds) for (let i = 0; i < 10; i++) names.push(`profile_${kind}_${i}`);
const expectedNames = new Set(names);
// Only firmware field NAMES are part of the reusable compatibility profile.
// Configuration IDs are learned from each authenticated device snapshot;
// never embed numeric IDs captured from a particular user's router.
export const EXPECTED_BLOCK_NAMES = Object.freeze([...expectedNames].sort());
const asciiDigits = value => typeof value === 'string' && value.length > 0 && !/[^0-9]/.test(value);
const byName = (a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
const byId = (a, b) => Number(a.id) - Number(b.id);

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

export function validateExactPattern(pattern) {
  if (!asciiDigits(pattern) || pattern.length > MAX_EXACT_PATTERN_LENGTH) {
    fail('INVALID_EXACT_PATTERN', 'An exact pattern must contain 1..32 ASCII digits without normalization');
  }
  return pattern;
}

/** Existing text is an opaque identity. Delete sends its rule ID, never this text. */
// Only fixed nine-digit domestic prefixes are admissible for new native masks.
 // Historical patterns remain opaque, deletable by their actual router ID.
 export function isFixedLengthNativePrefix(pattern) {
   return typeof pattern === 'string' && pattern.length === 9 && /^[0-9]{3,8}x{1,6}$/.test(pattern);
 }
 export function validateWritablePattern(pattern) {
   if (asciiDigits(pattern)) return validateExactPattern(pattern);
   if (isFixedLengthNativePrefix(pattern)) return pattern;
   fail('INVALID_EXACT_PATTERN', 'Use 1..32 exact digits or a nine-position prefix with 3..8 digits then lowercase x');
 }
 function checkPrefixOverlap(current, pattern) {
   if (!isFixedLengthNativePrefix(pattern)) return;
   const stem = pattern.slice(0, pattern.indexOf('x'));
   for (const rule of current.incoming) {
     const other = rule.pattern;
     if (asciiDigits(other)) {
       if (other.length === 9 && other.startsWith(stem)) fail('PREFIX_OVERLAP', 'An existing exact rule overlaps this native prefix');
       continue;
     }
     // Fail closed when another firmware-specific rule has unknown coverage.
     if (!isFixedLengthNativePrefix(other)) fail('PREFIX_EXISTING_PATTERN_UNVERIFIED', 'Existing native pattern coverage is not validated');
     const otherStem = other.slice(0, other.indexOf('x'));
     if (otherStem.startsWith(stem) || stem.startsWith(otherStem)) fail('PREFIX_OVERLAP', 'An existing native prefix overlaps this rule');
   }
 }
 
 export function validateExistingPattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > MAX_EXISTING_PATTERN_LENGTH) {
    fail('INVALID_EXISTING_PATTERN', 'An existing pattern must be a nonempty string of at most 4096 code units');
  }
  return pattern;
}

export function validateRuleId(id) {
  if (!asciiDigits(id) || id.length > 10 || (id.length > 1 && id[0] === '0') || BigInt(id) > 2147483647n) {
    fail('INVALID_RULE_ID', 'A rule ID must be a canonical nonnegative signed-32-bit integer string');
  }
  return id;
}

function readCounter(value) {
  if (value === '') return 0;
  if (!asciiDigits(value) || value.length > 3 || (value.length > 1 && value[0] === '0') || Number(value) > MAX_ENTRIES) {
    fail('INVALID_COUNTER', 'A counter must be empty or a canonical integer string in 0..100');
  }
  return Number(value);
}

/** Parse only the observed double-quoted addCfg format. No JavaScript is executed. */
export function parseBlockState(body) {
  if (typeof body !== 'string') fail('INVALID_CGI', 'Expected a CGI text response');
  const quoted = '"((?:\\\\.|[^"\\\\])*)"';
  const regex = new RegExp('addCfg\\(\\s*' + quoted + '\\s*,\\s*' + quoted + '\\s*,\\s*' + quoted + '\\s*\\)', 'g');
  const matches = [...body.matchAll(regex)];
  if (matches.length !== 242 || (body.match(/\baddCfg\s*\(/g) || []).length !== 242) {
    fail('INVALID_CGI', 'Expected exactly 242 recognized addCfg calls');
  }
  let rows;
  try {
    rows = matches.map(match => ({
      name: JSON.parse('"' + match[1] + '"'),
      id: JSON.parse('"' + match[2] + '"'),
      value: JSON.parse('"' + match[3] + '"'),
    }));
  } catch {
    fail('INVALID_CGI_STRING', 'An addCfg string is not valid in the supported format');
  }
  return validateState(rows).rows;
}

/**
 * Validate every field and return copies. Existing patterns are opaque strings:
 * only newly managed exact patterns have the 1..32 ASCII-digit restriction.
 * Rule IDs are conservatively required to be unique across both directions.
 */
export function validateState(rows) {
  if (!Array.isArray(rows) || rows.length !== 242) fail('INVALID_FIELD_COUNT', 'Expected 242 state rows');
  const seenNames = new Set();
  const seenConfigIds = new Set();
  const copied = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object' ||
        ['name', 'id', 'value'].some(key => typeof row[key] !== 'string')) {
      fail('INVALID_ROW', 'Every state row must have string name, id and value fields');
    }
    if (!expectedNames.has(row.name)) fail('UNKNOWN_FIELD', 'The state contains an unexpected field');
    if (seenNames.has(row.name)) fail('DUPLICATE_FIELD', 'A state field name is duplicated');
    if (!asciiDigits(row.id) || row.id.length !== 12) fail('INVALID_CONFIG_ID', 'Configuration IDs must contain 12 ASCII digits');
    if (seenConfigIds.has(row.id)) fail('DUPLICATE_CONFIG_ID', 'A configuration ID is duplicated');
    seenNames.add(row.name);
    seenConfigIds.add(row.id);
    copied.push({name: row.name, id: row.id, value: row.value});
  }
  copied.sort(byName);
  const fields = new Map(copied.map(row => [row.name, row]));
  const counters = {};
  const lists = {};
  const seenRuleIds = new Set();
  for (const direction of ['incoming', 'outgoing']) {
    const list = [];
    for (let slot = 0; slot < MAX_ENTRIES; slot++) {
      const field = `${direction}_entry_str_${slot}`;
      const value = fields.get(field).value;
      if (value === '') continue;
      const separator = value.indexOf('|');
      if (separator <= 0 || separator === value.length - 1) fail('INVALID_ENTRY', 'An occupied entry must have ID|pattern with a nonempty pattern');
      const id = validateRuleId(value.slice(0, separator));
      if (seenRuleIds.has(id)) fail('DUPLICATE_RULE_ID', 'A rule ID is duplicated in the block state');
      seenRuleIds.add(id);
      list.push({id, pattern: value.slice(separator + 1), field, slot});
    }
    counters[direction] = readCounter(fields.get(`${direction}_entry_num`).value);
    if (counters[direction] !== list.length) fail('COUNTER_MISMATCH', 'A list counter does not match its occupied entries');
    lists[direction] = list.sort(byId);
  }
  const profiles = Array.from({length: 10}, (_, index) => {
    const profile = {index};
    for (const kind of profileKinds) profile[kind] = fields.get(`profile_${kind}_${index}`).value;
    return profile;
  });
  return {
    rows: copied,
    schema: copied.map(({name, id}) => ({name, id})),
    incoming: lists.incoming,
    outgoing: lists.outgoing,
    counters,
    profiles,
  };
}

function hashSnapshot(state) {
  // Slot locations are representational. Schema identity, every logical entry,
  // every profile value and the validated numeric counters remain significant.
  const canonical = {
    version: 1,
    schema: state.schema.map(({name, id}) => [name, id]),
    incoming: state.incoming.map(({id, pattern}) => [id, pattern]),
    outgoing: state.outgoing.map(({id, pattern}) => [id, pattern]),
    counters: [state.counters.incoming, state.counters.outgoing],
    profiles: state.profiles.map(profile => [profile.index, ...profileKinds.map(kind => profile[kind])]),
  };
  return createHash('sha256').update(JSON.stringify(canonical), 'utf8').digest('hex');
}

export function stateHash(rows) {
  return hashSnapshot(validateState(rows));
}

export function assertSafePlanState(rows) {
  const state = validateState(rows);
  if (state.profiles.some(profile => profile.enable !== '0')) {
    fail('PROFILES_ENABLED', 'All profiles must be disabled for an individual incoming-rule management plan');
  }
  return state;
}

/** Optional target-specific preflight helpers; the manager must run these before POST. */
export function assertAddPreconditions(rows, pattern) {
  validateWritablePattern(pattern);
  const state = assertSafePlanState(rows);
  checkPrefixOverlap(state, pattern);
  if (state.incoming.some(entry => entry.pattern === pattern)) fail('PATTERN_ALREADY_PRESENT', 'The exact incoming pattern is already present');
  if (state.incoming.length >= MAX_ENTRIES) fail('INCOMING_CAPACITY', 'The incoming list is full');
  return state;
}

export function assertDeletePreconditions(rows, id, pattern) {
  validateRuleId(id);
  validateExistingPattern(pattern);
  const state = assertSafePlanState(rows);
  const entry = state.incoming.find(candidate => candidate.id === id);
  if (!entry) fail('DELETE_ID_NOT_FOUND', 'The selected incoming ID is absent');
  if (entry.pattern !== pattern) fail('DELETE_PATTERN_MISMATCH', 'The selected ID no longer identifies the expected literal pattern text');
  return state;
}

function listIssues(before, after, direction) {
  const issues = [];
  const old = new Map(before.map(entry => [entry.id, entry]));
  const current = new Map(after.map(entry => [entry.id, entry]));
  for (const entry of before) {
    if (!current.has(entry.id)) issues.push({code: 'ENTRY_REMOVED', direction, id: entry.id});
    else if (current.get(entry.id).pattern !== entry.pattern) issues.push({code: 'ENTRY_CHANGED', direction, id: entry.id});
  }
  for (const entry of after) if (!old.has(entry.id)) issues.push({code: 'ENTRY_ADDED', direction, id: entry.id});
  return issues;
}

function unrelatedIssues(before, after) {
  const issues = [];
  const schema = new Map(after.schema.map(row => [row.name, row.id]));
  for (const row of before.schema) {
    if (schema.get(row.name) !== row.id) issues.push({code: 'SCHEMA_CHANGED', field: row.name});
  }
  for (let index = 0; index < 10; index++) {
    for (const kind of profileKinds) {
      if (before.profiles[index][kind] !== after.profiles[index][kind]) {
        issues.push({code: 'PROFILE_CHANGED', field: `profile_${kind}_${index}`});
      }
    }
  }
  return issues.concat(listIssues(before.outgoing, after.outgoing, 'outgoing'));
}

/** Invalid states/preconditions throw; valid states with unexpected deltas return ok:false. */
export function validateAddDelta(beforeRows, afterRows, pattern) {
  validateWritablePattern(pattern);
  const before = assertSafePlanState(beforeRows);
  const after = validateState(afterRows);
  const issues = unrelatedIssues(before, after);
  const oldIds = new Set(before.incoming.map(entry => entry.id));
  const newlyAdded = after.incoming.filter(entry => !oldIds.has(entry.id));
  const hadPattern = before.incoming.some(entry => entry.pattern === pattern);
  if (hadPattern) issues.push({code: 'PATTERN_ALREADY_PRESENT'});
  const incomingChanges = listIssues(before.incoming, after.incoming, 'incoming');
  issues.push(...incomingChanges.filter(change => change.code !== 'ENTRY_ADDED'));
  if (newlyAdded.length !== 1) issues.push({code: 'ADD_COUNT_MISMATCH', actual: newlyAdded.length});
  else if (newlyAdded[0].pattern !== pattern) issues.push({code: 'ADDED_PATTERN_MISMATCH', id: newlyAdded[0].id});
  const added = !hadPattern && newlyAdded.length === 1 && newlyAdded[0].pattern === pattern ? {...newlyAdded[0]} : null;
  return {ok: issues.length === 0, issues, added, beforeHash: hashSnapshot(before), afterHash: hashSnapshot(after)};
}

export function validateDeleteDelta(beforeRows, afterRows, id, pattern) {
  validateRuleId(id);
  validateExistingPattern(pattern);
  const before = assertSafePlanState(beforeRows);
  const after = validateState(afterRows);
  const issues = unrelatedIssues(before, after);
  const selected = before.incoming.find(entry => entry.id === id);
  if (!selected) issues.push({code: 'DELETE_ID_NOT_FOUND'});
  else if (selected.pattern !== pattern) issues.push({code: 'DELETE_PATTERN_MISMATCH'});
  if (after.incoming.some(entry => entry.id === id)) issues.push({code: 'DELETE_TARGET_REMAINS', id});
  const expectedRemaining = before.incoming.filter(entry => entry.id !== id);
  const actualRemaining = after.incoming.filter(entry => entry.id !== id);
  issues.push(...listIssues(expectedRemaining, actualRemaining, 'incoming'));
  const removed = selected && selected.pattern === pattern && !after.incoming.some(entry => entry.id === id) ? {...selected} : null;
  return {ok: issues.length === 0, issues, removed, beforeHash: hashSnapshot(before), afterHash: hashSnapshot(after)};
}
