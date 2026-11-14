/**
 * Command blocklist bypass regression tests.
 *
 * Source: GHSA-vwjq-wx58-g4qr (duplicate: GHSA-qfrw-33vj-p9v2) — dangerous
 * commands were only matched as bare names, so `/bin/rm`, `./rm`, `python3`,
 * `cmd.exe` etc. passed. The sync and async validators also disagreed.
 */

const MCPSanitizer = require('../src/index');
const lib = require('../src/index');
const { isDangerousCommand, commandBaseName } = require('../src/utils/validation-utils');

const sanitizer = new MCPSanitizer('PRODUCTION');

const entryPoints = {
  'sanitize(type: command)': async (c) => sanitizer.sanitize(c, { type: 'command' }).blocked === true,
  'sanitize(request_body.command)': async (c) =>
    sanitizer.sanitize({ command: c }, { type: 'request_body' }).blocked === true,
  'CommandValidator.validate': async (c) => !(await new lib.CommandValidator().validate(c)).isValid,
  validateCommand: async (c) => !(await lib.validateCommand(c)).isValid
};

const bypasses = [
  '/bin/rm -rf /tmp/x',
  '/usr/bin/rm -rf /tmp/x',
  './rm -rf x',
  '/bin/sh -c id',
  '/usr/bin/bash -c id',
  '/usr/bin/curl http://example.com/x',
  'RM -rf x',
  'rm.exe -rf x',
  'python3 -c id',
  'python3.11 -c id',
  '/usr/bin/python3 -c id',
  'perl -e id',
  'ruby -e id',
  'php -r id',
  'zsh -c id',
  'busybox sh',
  'nodejs script.js',
  'pythonw x.py',
  'pypy3 x.py',
  'deno run x.ts',
  'bun x.ts',
  'rbash',
  'wsl ls',
  'osascript x.scpt',
  'cmd.exe /c dir',
  'bash.exe -c id',
  'C:\\Windows\\System32\\cmd.exe /c dir',
  'env python3 -c id',
  'nohup /bin/sh -c id',
  'timeout 5 sh -c id',
  'env -i X=1 /bin/sh',
  "'rm' -rf x",
  '"/bin/r"m -rf x'
];

const safe = [
  'ls -la', 'git status', 'echo hello', 'cat README.md', 'grep -r foo src',
  // a path argument is not the program, even if its basename is a blocked name
  'ls /home/user/node', 'cat logs/ssh', 'ls bin/sh'
];

describe('Command blocklist bypass (GHSA-vwjq-wx58-g4qr)', () => {
  describe.each(Object.entries(entryPoints))('%s', (_name, isBlocked) => {
    it.each(bypasses)('blocks %s', async (cmd) => {
      expect(await isBlocked(cmd)).toBe(true);
    });

    it.each(safe)('allows %s', async (cmd) => {
      expect(await isBlocked(cmd)).toBe(false);
    });
  });

  describe('isDangerousCommand', () => {
    it.each([
      ['/bin/rm', 'rm'],
      ['C:\\Windows\\System32\\CMD.EXE', 'cmd'],
      ['"./bash"', 'bash'],
      ['python3.11', 'python3.11']
    ])('normalizes %s to %s', (token, name) => {
      expect(commandBaseName(token)).toBe(name);
    });

    it('matches version suffixes and mkfs variants', () => {
      expect(isDangerousCommand('python3.11')).toBe(true);
      expect(isDangerousCommand('mkfs.ext4')).toBe(true);
    });

    it('does not match names that only start with a blocked name', () => {
      expect(isDangerousCommand('shasum')).toBe(false);
      expect(isDangerousCommand('rmdir-safe')).toBe(false);
      expect(isDangerousCommand('ls')).toBe(false);
    });

    it('strips version suffixes in linear time', () => {
      const start = Date.now();
      isDangerousCommand('-'.repeat(50000) + '!');
      expect(Date.now() - start).toBeLessThan(100);
    });

    it('strips quotes in linear time', () => {
      const start = Date.now();
      commandBaseName('"'.repeat(50000) + 'x');
      expect(Date.now() - start).toBeLessThan(100);
    });

    it('accepts a custom list', () => {
      expect(isDangerousCommand('/sbin/reboot', ['reboot'])).toBe(true);
      expect(isDangerousCommand('/bin/rm', ['reboot'])).toBe(false);
    });
  });
});

describe('allowlists written before 1.4.4 keep working', () => {
  it('allows an explicitly allowlisted interpreter', async () => {
    const v = new lib.CommandValidator({ allowedCommands: ['php', 'git'] });
    expect((await v.validate('php artisan migrate')).isValid).toBe(true);
    expect((await v.validate('lua x.lua')).isValid).toBe(false);
  });

  it('does not let an allowlist override the original blocklist', async () => {
    expect((await new lib.CommandValidator({ allowedCommands: ['rm'] }).validate('rm x')).isValid).toBe(false);
  });

  it('honours a custom blocklist over the allowlist', async () => {
    const v = new lib.CommandValidator({ allowedCommands: ['php'], blockedCommands: ['php'] });
    expect((await v.validate('php artisan')).isValid).toBe(false);
  });
});

describe('policies that disable commands say so', () => {
  it('reports maxCommandLength 0 clearly', async () => {
    const result = await new lib.CommandValidator({ maxCommandLength: 0 }).validate('ls -la');
    expect(result.isValid).toBe(false);
    expect(result.warnings[0]).toMatch(/disabled by this policy/);
  });
});
