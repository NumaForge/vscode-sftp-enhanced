/*
 * Unit test del credential manager (modello 2b: passphrase master -> scrypt ->
 * AES-256-GCM). Nessun accesso alla home reale: gli store vengono rediretti su
 * directory temporanee; vscode viene iniettato come mock.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const credManager = require('../src/modules/credManager');
const { __test } = credManager;

const MASTER = 'passphrase-di-prova';

let tmpNew;
let tmpLegacy;

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/**
 * Mock minimale di vscode: showInputBox consuma una coda di risposte
 * (undefined = utente annulla), i messaggi vengono raccolti per le assert.
 */
function installMockVscode(inputQueue, options) {
  const opts = options || {};
  const calls = { prompts: [], errors: [], warnings: [], infos: [], quickPicks: [] };
  __test._setVscode({
    window: {
      showInputBox: cfg => {
        calls.prompts.push((cfg && cfg.prompt) || '');
        return Promise.resolve(inputQueue.shift());
      },
      showErrorMessage: msg => {
        calls.errors.push(msg);
        return Promise.resolve(undefined);
      },
      showWarningMessage: msg => {
        calls.warnings.push(msg);
        return Promise.resolve(opts.warningAnswer);
      },
      showInformationMessage: msg => {
        calls.infos.push(msg);
        return Promise.resolve(undefined);
      },
      showQuickPick: items => {
        calls.quickPicks.push(items);
        return Promise.resolve(opts.quickPickAnswer);
      },
    },
    commands: {
      registerCommand: () => ({ dispose: () => undefined }),
    },
  });
  return calls;
}

/** Esegue il primo setup della master + salvataggio password per host. */
async function seedMasterAndHost(host, hostPw) {
  const calls = installMockVscode([MASTER, MASTER, hostPw]);
  const pw = await credManager.askPassword(`[${host}]: Password:`);
  return { pw, calls };
}

beforeEach(() => {
  tmpNew = mkTmp('sftp-enh-creds-');
  tmpLegacy = mkTmp('sftp-cobol-creds-');
  __test._reset();
  __test._setStoreDirs(tmpNew, tmpLegacy);
});

afterEach(() => {
  fs.rmSync(tmpNew, { recursive: true, force: true });
  fs.rmSync(tmpLegacy, { recursive: true, force: true });
});

describe('crypto helpers', () => {
  const SALT = Buffer.from('un-salt-di-prova').toString('base64');

  test('deriveKey e\' deterministica a parita\' di passphrase e salt', () => {
    const k1 = __test.deriveKey(MASTER, SALT);
    const k2 = __test.deriveKey(MASTER, SALT);
    expect(k1.length).toBe(32);
    expect(k1.equals(k2)).toBe(true);
  });

  test('deriveKey cambia al cambiare del salt', () => {
    const other = Buffer.from('un-altro-salt---').toString('base64');
    expect(__test.deriveKey(MASTER, SALT).equals(__test.deriveKey(MASTER, other))).toBe(false);
  });

  test('deriveKey cambia al cambiare della passphrase', () => {
    expect(__test.deriveKey(MASTER, SALT).equals(__test.deriveKey('altra-pass', SALT))).toBe(false);
  });

  test('encrypt/decrypt: roundtrip', () => {
    const key = __test.deriveKey(MASTER, SALT);
    const blob = __test.encrypt(key, 'segretissima');
    expect(__test.decrypt(key, blob)).toBe('segretissima');
  });

  test('encrypt: iv casuale, stessi dati -> blob diversi', () => {
    const key = __test.deriveKey(MASTER, SALT);
    const a = __test.encrypt(key, 'x');
    const b = __test.encrypt(key, 'x');
    expect(a.iv).not.toBe(b.iv);
    expect(a.ct).not.toBe(b.ct);
  });

  test('decrypt con chiave sbagliata lancia (tag GCM invalido)', () => {
    const key = __test.deriveKey(MASTER, SALT);
    const wrong = __test.deriveKey('altra-pass', SALT);
    const blob = __test.encrypt(key, 'segreto');
    expect(() => __test.decrypt(wrong, blob)).toThrow();
  });

  test('decrypt con ciphertext manomesso lancia', () => {
    const key = __test.deriveKey(MASTER, SALT);
    const blob = __test.encrypt(key, 'segreto');
    const tampered = Buffer.from(blob.ct, 'base64');
    tampered[0] = tampered[0] ^ 0xff;
    blob.ct = tampered.toString('base64');
    expect(() => __test.decrypt(key, blob)).toThrow();
  });

  test('verifyKey: true con la chiave giusta, false con quella sbagliata', () => {
    const key = __test.deriveKey(MASTER, SALT);
    const st = { verifier: __test.encrypt(key, __test.VERIFIER_PLAINTEXT) };
    expect(__test.verifyKey(key, st)).toBe(true);
    expect(__test.verifyKey(__test.deriveKey('altra-pass', SALT), st)).toBe(false);
  });
});

describe('parseHost', () => {
  test('estrae l\'host dal prompt "[host]: ..."', () => {
    expect(__test.parseHost('[srv01]: Password:')).toBe('srv01');
  });

  test('estrae FQDN con punti e trattini', () => {
    expect(__test.parseHost('[amlif700bts001.example.it]: password for user:')).toBe(
      'amlif700bts001.example.it'
    );
  });

  test('null senza prefisso [host]', () => {
    expect(__test.parseHost('Password:')).toBeNull();
  });

  test('null su input vuoto o mancante', () => {
    expect(__test.parseHost('')).toBeNull();
    expect(__test.parseHost(undefined)).toBeNull();
  });
});

describe('isAuthFailure', () => {
  test.each([
    'All configured authentication methods failed',
    'Permission denied',
    'auth fail',
    'Authentication failure for user x',
  ])('true per "%s"', msg => {
    expect(__test.isAuthFailure(msg)).toBe(true);
  });

  test.each([
    'connect ECONNREFUSED 10.0.0.1:22',
    'Timed out while waiting for handshake',
    'getaddrinfo ENOTFOUND host',
  ])('false per errori di rete "%s"', msg => {
    expect(__test.isAuthFailure(msg)).toBe(false);
  });

  test('false per annullamento utente (cancelled)', () => {
    expect(__test.isAuthFailure('Connection cancelled by user')).toBe(false);
  });

  test('false per messaggio vuoto o mancante', () => {
    expect(__test.isAuthFailure('')).toBe(false);
    expect(__test.isAuthFailure(undefined)).toBe(false);
  });
});

describe('persistenza store', () => {
  const dummyStore = () => {
    const key = __test.deriveKey(MASTER, Buffer.from('salt-per-storage').toString('base64'));
    return {
      v: 1,
      kdf: { alg: 'scrypt', N: 16384, r: 8, p: 1, keylen: 32, salt: 'c2FsdA==' },
      verifier: __test.encrypt(key, __test.VERIFIER_PLAINTEXT),
      hosts: {},
    };
  };

  test('saveStore/loadStore: roundtrip', () => {
    const st = dummyStore();
    __test.saveStore(st);
    expect(__test.loadStore()).toEqual(st);
  });

  test('loadStore: null se lo store non esiste', () => {
    expect(__test.loadStore()).toBeNull();
  });

  test('loadStore: null su JSON corrotto o struttura non valida', () => {
    fs.mkdirSync(tmpNew, { recursive: true });
    fs.writeFileSync(__test.storePath(), '{non-json');
    expect(__test.loadStore()).toBeNull();
    fs.writeFileSync(__test.storePath(), JSON.stringify({ qualcosa: 1 }));
    expect(__test.loadStore()).toBeNull();
  });

  test('deleteStore rimuove il file', () => {
    __test.saveStore(dummyStore());
    expect(fs.existsSync(__test.storePath())).toBe(true);
    __test.deleteStore();
    expect(fs.existsSync(__test.storePath())).toBe(false);
  });

  test('migrazione: importa lo store legacy e lo copia nel percorso nuovo', () => {
    const st = dummyStore();
    fs.mkdirSync(tmpLegacy, { recursive: true });
    fs.writeFileSync(__test.legacyStorePath(), JSON.stringify(st));
    const loaded = __test.loadStore();
    expect(loaded).toEqual(st);
    // copiato nel nuovo percorso...
    expect(fs.existsSync(__test.storePath())).toBe(true);
    // ...senza cancellare il legacy (rollback possibile)
    expect(fs.existsSync(__test.legacyStorePath())).toBe(true);
  });

  test('migrazione: lo store nuovo ha precedenza sul legacy', () => {
    const stNew = dummyStore();
    const stLegacy = dummyStore();
    stLegacy.hosts = { legacyhost: stLegacy.verifier };
    __test.saveStore(stNew);
    fs.mkdirSync(tmpLegacy, { recursive: true });
    fs.writeFileSync(__test.legacyStorePath(), JSON.stringify(stLegacy));
    expect(__test.loadStore()).toEqual(stNew);
  });

  test('migrazione: legacy corrotto -> primo setup (null)', () => {
    fs.mkdirSync(tmpLegacy, { recursive: true });
    fs.writeFileSync(__test.legacyStorePath(), 'garbage');
    expect(__test.loadStore()).toBeNull();
  });
});

describe('askPassword (flusso completo, vscode mockato)', () => {
  test('primo setup: crea master, chiede e salva la password host cifrata', async () => {
    const { pw, calls } = await seedMasterAndHost('srv01', 'pw-host-1');
    expect(pw).toBe('pw-host-1');
    // 3 prompt: master, conferma, password host
    expect(calls.prompts.length).toBe(3);
    // lo store esiste e NON contiene la password in chiaro
    const raw = fs.readFileSync(__test.storePath(), 'utf8');
    expect(raw).not.toContain('pw-host-1');
    expect(JSON.parse(raw).hosts.srv01).toBeDefined();
  });

  test('richieste successive per lo stesso host: nessun nuovo prompt', async () => {
    await seedMasterAndHost('srv01', 'pw-host-1');
    const calls = installMockVscode([]); // nessuna risposta disponibile
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBe('pw-host-1');
    expect(calls.prompts.length).toBe(0);
  });

  test('host diverso: chiede solo la password del nuovo host', async () => {
    await seedMasterAndHost('srv01', 'pw-host-1');
    const calls = installMockVscode(['pw-host-2']);
    const pw = await credManager.askPassword('[srv02]: Password:');
    expect(pw).toBe('pw-host-2');
    expect(calls.prompts.length).toBe(1);
  });

  test('prompt di passphrase chiave privata: passthrough senza store', async () => {
    const calls = installMockVscode(['una-passphrase-chiave']);
    const pw = await credManager.askPassword('[srv01]: Enter your passphrase:');
    expect(pw).toBe('una-passphrase-chiave');
    expect(fs.existsSync(__test.storePath())).toBe(false);
    expect(calls.prompts.length).toBe(1);
  });

  test('prompt non riconosciuto (senza [host]): fallback al prompt classico', async () => {
    installMockVscode(['pw-generica']);
    const pw = await credManager.askPassword('Password:');
    expect(pw).toBe('pw-generica');
    expect(fs.existsSync(__test.storePath())).toBe(false);
  });

  test('utente annulla la master: ritorna undefined (collegamento annullato)', async () => {
    installMockVscode([undefined]);
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBeUndefined();
  });

  test('passphrase troppo corta al primo setup: errore e nessuno store', async () => {
    const calls = installMockVscode(['corta']);
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBeUndefined();
    expect(calls.errors.some(m => /troppo corta/i.test(m))).toBe(true);
    expect(fs.existsSync(__test.storePath())).toBe(false);
  });

  test('sblocco con master errata 3 volte: fallisce e suggerisce il reset', async () => {
    await seedMasterAndHost('srv01', 'pw-host-1');
    __test._reset(); // nuova "sessione": la master va reinserita
    const calls = installMockVscode(['sbagliata1', 'sbagliata2', 'sbagliata3']);
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBeUndefined();
    expect(calls.warnings.length).toBe(3);
    expect(calls.errors.some(m => /Reset Credentials/.test(m))).toBe(true);
  });

  test('sblocco con master corretta in nuova sessione: password dallo store', async () => {
    await seedMasterAndHost('srv01', 'pw-host-1');
    __test._reset();
    const calls = installMockVscode([MASTER]);
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBe('pw-host-1');
    expect(calls.prompts.length).toBe(1); // solo la master
  });
});

describe('onConnectError (lock host su auth-fail)', () => {
  test('auth-fail blocca l\'host e al prompt successivo chiede una password NUOVA', async () => {
    await seedMasterAndHost('srv01', 'pw-vecchia');
    installMockVscode([]);
    credManager.onConnectError('srv01', new Error('All configured authentication methods failed'));
    expect(__test._state().locked).toContain('srv01');

    const calls = installMockVscode(['pw-nuova']);
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBe('pw-nuova');
    expect(calls.prompts.some(p => /errata o scaduta/.test(p))).toBe(true);
    expect(__test._state().locked).not.toContain('srv01');
  });

  test('errore di rete: NON blocca l\'host', async () => {
    await seedMasterAndHost('srv01', 'pw-host-1');
    installMockVscode([]);
    credManager.onConnectError('srv01', new Error('connect ECONNREFUSED 10.0.0.1:22'));
    expect(__test._state().locked).not.toContain('srv01');
    // e la password in cache continua a essere servita senza prompt
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBe('pw-host-1');
  });

  test('host mancante: nessun effetto e nessuna eccezione', () => {
    installMockVscode([]);
    expect(() => credManager.onConnectError(undefined, new Error('authentication'))).not.toThrow();
    expect(__test._state().locked.length).toBe(0);
  });
});

describe('comandi', () => {
  test('runUpdatePassword aggiorna la password di un host bloccato e lo sblocca', async () => {
    await seedMasterAndHost('srv01', 'pw-vecchia');
    installMockVscode([]);
    credManager.onConnectError('srv01', new Error('auth fail'));

    const calls = installMockVscode(['pw-aggiornata']);
    await credManager.runUpdatePassword('srv01');
    expect(calls.infos.some(m => /password aggiornata per srv01/.test(m))).toBe(true);
    expect(__test._state().locked).not.toContain('srv01');

    installMockVscode([]);
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBe('pw-aggiornata');
  });

  test('runResetCredentials (confermato) cancella store e stato', async () => {
    await seedMasterAndHost('srv01', 'pw-host-1');
    installMockVscode([], { warningAnswer: 'Azzera' });
    await credManager.runResetCredentials();
    expect(fs.existsSync(__test.storePath())).toBe(false);
    expect(__test._state().hasKey).toBe(false);
    expect(__test._state().hosts).toBeNull();
  });

  test('runResetCredentials annullato: non tocca nulla', async () => {
    await seedMasterAndHost('srv01', 'pw-host-1');
    installMockVscode([], { warningAnswer: undefined });
    await credManager.runResetCredentials();
    expect(fs.existsSync(__test.storePath())).toBe(true);
    expect(__test._state().hasKey).toBe(true);
  });

  test('activate registra i comandi update/reset nelle subscriptions', () => {
    const registered = [];
    __test._setVscode({
      commands: {
        registerCommand: id => {
          registered.push(id);
          return { dispose: () => undefined };
        },
      },
      window: {},
    });
    const context = { subscriptions: [] };
    credManager.activate(context);
    expect(registered).toEqual(['sftpEnhanced.updatePassword', 'sftpEnhanced.resetCredentials']);
    expect(context.subscriptions.length).toBe(2);
  });
});

describe('migrazione end-to-end', () => {
  test('store legacy (~/.sftp-cobol-creds): stessa master, password riutilizzate', async () => {
    // 1) crea uno store "legacy" completo usando il flusso normale...
    await seedMasterAndHost('srv01', 'pw-legacy');
    // 2) ...spostalo nel percorso legacy e svuota il nuovo
    fs.mkdirSync(tmpLegacy, { recursive: true });
    fs.copyFileSync(__test.storePath(), __test.legacyStorePath());
    fs.unlinkSync(__test.storePath());
    __test._reset();
    // 3) nuova sessione: basta la vecchia master, la password host arriva dallo store migrato
    installMockVscode([MASTER]);
    const pw = await credManager.askPassword('[srv01]: Password:');
    expect(pw).toBe('pw-legacy');
    expect(fs.existsSync(__test.storePath())).toBe(true);
  });
});
