/**
 * File path / sensitive-file access validation regression tests.
 *
 * Asserts CORRECT (post-fix) behavior, so these are RED until the fix lands.
 * Source: GHSA-7w82-6f9j-v9jp (EQSTLab / SK Shieldus) — file path sanitizer
 * permits arbitrary user-home absolute paths (CWE-22).
 *
 * Fix direction: drop `/home/` and `/Users/` from the absolute-path allowlist
 * and add a sensitive-file/dotdir blocklist. A `blocked: true` result is the
 * boundary consumers rely on before reading/writing a path for `file_reader` /
 * `file_writer` tools.
 */

const MCPSanitizer = require('../src/index');

const sanitizer = new MCPSanitizer();

function isBlocked (path) {
  return sanitizer.sanitize(path, { type: 'file_path' }).blocked === true;
}

describe('Path traversal: sensitive file access (GHSA-7w82-6f9j-v9jp)', () => {
  describe('baseline — already blocked (regression guard)', () => {
    const alreadyBlocked = [
      '/etc/passwd',
      '/root/.ssh/id_rsa',
      '/proc/self/environ'
    ];

    it.each(alreadyBlocked)('blocks %s', (path) => {
      expect(isBlocked(path)).toBe(true);
    });
  });

  describe('reported bypasses — sensitive user-home files must be blocked', () => {
    const reportedBypasses = [
      '/home/victim/.ssh/id_rsa',
      '/home/victim/.aws/credentials',
      '/Users/victim/.ssh/id_rsa',
      '/home/victim/.gnupg/secring.gpg',
      '/home/victim/.kube/config',
      '/home/victim/.config/gcloud/credentials.db',
      '/home/victim/.npmrc',
      '/home/victim/.netrc',
      '/home/victim/.env'
    ];

    it.each(reportedBypasses)('blocks %s', (path) => {
      expect(isBlocked(path)).toBe(true);
    });
  });
});

describe('Sensitive path as first segment (GHSA-6xj4-4chr-656w)', () => {
  // The 1.4.0 denylist matched `/`-prefixed substrings, so relative paths whose
  // first segment is sensitive passed with blocked=false.
  describe('reported bypasses — must be blocked', () => {
    const reportedBypasses = [
      '.env',
      './.env',
      '.npmrc',
      '.netrc',
      '.ssh/id_rsa',
      '.aws/credentials',
      '.docker/config.json',
      '.git-credentials',
      '.gnupg/secring.gpg',
      '.kube/config'
    ];

    it.each(reportedBypasses)('blocks %s', (path) => {
      expect(isBlocked(path)).toBe(true);
    });
  });

  describe('spelling variants — must be blocked', () => {
    const variants = [
      '.ENV',
      '.env.production',
      '.env.',
      '.ssh',
      'sub/.ssh',
      'sub\\.ssh\\id_rsa'
    ];

    it.each(variants)('blocks %s', (path) => {
      expect(isBlocked(path)).toBe(true);
    });
  });

  describe('look-alike names — must be allowed', () => {
    // Previously over-blocked by the `/.env` substring match.
    const allowed = [
      'sub/.environment/notes.txt',
      'docs/env.txt',
      'data/ssh-notes.txt'
    ];

    it.each(allowed)('allows %s', (path) => {
      expect(isBlocked(path)).toBe(false);
    });
  });
});
