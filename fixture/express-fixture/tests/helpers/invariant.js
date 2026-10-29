function invariant(id, condition, detail) {
  if (!condition) {
    throw new Error(`SECURITY_INVARIANT_VIOLATED:${id}: ${detail}`);
  }
}

module.exports = { invariant };
