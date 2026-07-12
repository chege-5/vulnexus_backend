function makeResetToken(userId) {
  const suffix = Math.random().toString(36).slice(2);
  return `${userId}-${Date.now()}-${suffix}`;
}
