import {execFileSync, spawnSync} from 'node:child_process'
import {mkdtempSync, rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {test} from 'node:test'

const PACKAGE = path.join(import.meta.dirname, '..')
const COMPILER = process.env.CXX ?? 'c++'
const available = spawnSync(COMPILER, ['--version']).status === 0

/**
 * The sealed payload's format is C++ the binding runs (cpp/VaultPayload.hpp): test/payload.cpp holds it to its layouts,
 * old entries among them, with the system's compiler. Skipped where there is none.
 */
test('the sealed payload reads every version it wrote, and nothing else', {
  skip: !available && `no ${COMPILER}`,
}, () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'crypto-vault-payload-'))
  const binary = path.join(directory, 'payload')

  try {
    execFileSync(COMPILER, [
      '-std=c++17',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-I',
      path.join(PACKAGE, 'cpp'),
      path.join(PACKAGE, 'test/payload.cpp'),
      '-o',
      binary,
    ])
    execFileSync(binary, {stdio: 'pipe'})
  } finally {
    rmSync(directory, {force: true, recursive: true})
  }
})
