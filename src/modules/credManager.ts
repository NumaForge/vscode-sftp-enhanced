/*
 * credManager
 * -----------------------------------------------------------------------------
 * Gestione delle password SFTP con cifratura "modello 2b":
 *
 *   - Una PASSPHRASE MASTER (scelta dall'utente) protegge tutte le password.
 *     La master NON viene mai salvata: da essa si deriva (scrypt) la chiave
 *     AES-256-GCM con cui si cifrano le password dei singoli host.
 *   - Le password cifrate stanno in un file locale (store.json). Il file, da
 *     solo, e' inutile senza la master -> non e' auto-decifrabile da malware
 *     che copia il blob (a differenza di DPAPI/Credential Manager).
 *   - Zero richieste durante la sessione: si inserisce la master UNA volta,
 *     poi tutte le connessioni (tutti gli host) usano le password decifrate
 *     in memoria.
 *
 * Requisiti implementati:
 *   1. Su fallimento di autenticazione (password errata/scaduta) NON si
 *      ritenta a ripetizione: l'host viene "bloccato" e si chiede di
 *      aggiornare la password (niente rischio lockout da retry automatici).
 *   2. Comando per aggiornare la password di un host (scadenza password).
 *   3. Comando di reset totale: cancella master + tutte le password
 *      (NON tocca la configurazione host/profili di sftp.json).
 *
 * Lo store vive in ~/.sftp-enhanced-creds; al primo avvio viene importato in
 * modo trasparente l'eventuale store legacy ~/.sftp-cobol-creds (versione
 * distribuita come patch dell'estensione originale).
 * -----------------------------------------------------------------------------
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  COMMAND_RESET_CREDENTIALS,
  COMMAND_UPDATE_PASSWORD,
  EXTENSION_DISPLAY_NAME,
} from '../constants';

// vscode viene risolto solo dentro il process host: require lazy cosi' il
// modulo resta caricabile anche in un test Node puro (dove si inietta un mock).
let _vscode: any = null;
function vscode(): any {
  if (!_vscode) _vscode = require('vscode');
  return _vscode;
}

// --- Parametri e percorsi -----------------------------------------------------

const STORE_FILENAME = 'store.json';
let storeDir = path.join(os.homedir(), '.sftp-enhanced-creds');
let legacyStoreDir = path.join(os.homedir(), '.sftp-cobol-creds');
function storePath(): string {
  return path.join(storeDir, STORE_FILENAME);
}
function legacyStorePath(): string {
  return path.join(legacyStoreDir, STORE_FILENAME);
}

const STORE_VERSION = 1;
// NON cambiare: questa costante e' cifrata dentro il verifier degli store gia'
// esistenti presso gli utenti (creati dalla versione patch "sftp-cobol").
// Cambiarla renderebbe irriconoscibile la passphrase master dopo la migrazione.
const VERIFIER_PLAINTEXT = 'sftp-cobol-cred-manager:v1';
const KDF = { alg: 'scrypt', N: 16384, r: 8, p: 1, keylen: 32 };
const MIN_PASSPHRASE_LEN = 8;
const MASTER_MAX_ATTEMPTS = 3;
const TOAST_DEBOUNCE_MS = 8000;
const MSG = EXTENSION_DISPLAY_NAME; // prefisso dei messaggi utente

// --- Stato di sessione (solo in memoria) --------------------------------------

let sessionKey: Buffer | null = null; // chiave AES derivata dalla master
let store: any = null; // contenuto di store.json (payload cifrati)
const lockedHosts = new Set<string>(); // host con auth fallita: non ritentare
const lastToastAt = new Map<string, number>(); // host -> ts ultimo avviso
let unlockInFlight: Promise<boolean> | null = null; // single-flight prompt master
const pwInFlight = new Map<string, Promise<string | undefined>>(); // 1 prompt per host

// --- Crypto helpers (puri, unit-testabili) -----------------------------------

function deriveKey(passphrase: string, saltB64: string): Buffer {
  const salt = Buffer.from(saltB64, 'base64');
  // cast: @types/node v9 non conosce scryptSync (Node >=10.5, ok nel runtime VS Code)
  return (crypto as any).scryptSync(Buffer.from(String(passphrase), 'utf8'), salt, KDF.keylen, {
    N: KDF.N,
    r: KDF.r,
    p: KDF.p,
    maxmem: 128 * 1024 * 1024,
  });
}

function encrypt(key: Buffer, plaintext: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('base64'), tag: tag.toString('base64'), ct: ct.toString('base64') };
}

function decrypt(key: Buffer, obj: { iv: string; tag: string; ct: string }): string {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(obj.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(obj.tag, 'base64'));
  const pt = Buffer.concat([decipher.update(Buffer.from(obj.ct, 'base64')), decipher.final()]);
  return pt.toString('utf8');
}

function verifyKey(key: Buffer, st: any): boolean {
  try {
    return decrypt(key, st.verifier) === VERIFIER_PLAINTEXT;
  } catch (_e) {
    return false; // tag GCM non valido -> passphrase errata
  }
}

// --- Persistenza --------------------------------------------------------------

function readStoreFile(file: string): any {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (parsed && parsed.kdf && parsed.verifier) return parsed;
    return null;
  } catch (_e) {
    return null; // file assente o illeggibile
  }
}

function loadStore(): any {
  const current = readStoreFile(storePath());
  if (current) return current;
  // Migrazione trasparente dallo store legacy (~/.sftp-cobol-creds): stessa
  // struttura e stesso verifier, quindi la master dell'utente continua a valere.
  // Il file legacy non viene cancellato (rollback possibile).
  const legacy = readStoreFile(legacyStorePath());
  if (legacy) {
    try {
      saveStore(legacy);
    } catch (_e) {
      // migrazione fallita: si continua a lavorare sul contenuto legacy in memoria
    }
    return legacy;
  }
  return null;
}

function saveStore(st: any): void {
  // cast: @types/node v9 non conosce l'opzione recursive (Node >=10.12, ok nel runtime VS Code)
  (fs.mkdirSync as any)(storeDir, { recursive: true });
  const tmp = storePath() + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(st, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmp, storePath());
  try {
    fs.chmodSync(storePath(), 0o600);
  } catch (_e) {
    /* Windows: ACL profilo utente */
  }
}

function deleteStore(): void {
  try {
    fs.unlinkSync(storePath());
  } catch (_e) {
    /* gia' assente */
  }
}

// --- Utilita' UI --------------------------------------------------------------

function inputPassword(prompt: string, extra?: object): Promise<string | undefined> {
  const opts = Object.assign({ ignoreFocusOut: true, password: true, prompt }, extra || {});
  return Promise.resolve(vscode().window.showInputBox(opts));
}

function parseHost(promptStr: string): string | null {
  // I prompt password/passphrase dell'estensione iniziano con "[<host>]: ..."
  const m = /^\[([^\]]+)\]/.exec(String(promptStr || ''));
  return m ? m[1] : null;
}

// --- Unlock / primo setup della master ---------------------------------------

async function firstSetup(): Promise<boolean> {
  const v = vscode();
  const p1 = await inputPassword(
    `Crea una passphrase MASTER (min ${MIN_PASSPHRASE_LEN} caratteri) per cifrare le password SFTP. Non verra' salvata.`
  );
  if (p1 === undefined) return false; // annullato
  if (p1.length < MIN_PASSPHRASE_LEN) {
    v.window.showErrorMessage(`Passphrase troppo corta (min ${MIN_PASSPHRASE_LEN}).`);
    return false;
  }
  const p2 = await inputPassword('Conferma la passphrase MASTER.');
  if (p2 === undefined) return false;
  if (p1 !== p2) {
    v.window.showErrorMessage('Le due passphrase non coincidono.');
    return false;
  }
  const salt = crypto.randomBytes(16).toString('base64');
  const key = deriveKey(p1, salt);
  store = {
    v: STORE_VERSION,
    kdf: { alg: KDF.alg, N: KDF.N, r: KDF.r, p: KDF.p, keylen: KDF.keylen, salt },
    verifier: encrypt(key, VERIFIER_PLAINTEXT),
    hosts: {},
  };
  saveStore(store);
  sessionKey = key;
  return true;
}

async function unlockExisting(): Promise<boolean> {
  const v = vscode();
  for (let attempt = 1; attempt <= MASTER_MAX_ATTEMPTS; attempt++) {
    const p = await inputPassword('Inserisci la passphrase MASTER per sbloccare le password SFTP.');
    if (p === undefined) return false; // annullato: nessun collegamento
    const key = deriveKey(p, store.kdf.salt);
    if (verifyKey(key, store)) {
      sessionKey = key;
      return true;
    }
    const left = MASTER_MAX_ATTEMPTS - attempt;
    v.window.showWarningMessage(`Passphrase errata.${left > 0 ? ` Tentativi rimasti: ${left}.` : ''}`);
  }
  v.window.showErrorMessage(
    `Passphrase errata piu' volte. Se l'hai dimenticata usa il comando "${MSG}: Reset Credentials".`
  );
  return false;
}

function ensureUnlocked(): Promise<boolean> {
  if (sessionKey) return Promise.resolve(true);
  if (unlockInFlight) return unlockInFlight;
  unlockInFlight = (async () => {
    try {
      store = loadStore();
      return store ? await unlockExisting() : await firstSetup();
    } finally {
      unlockInFlight = null;
    }
  })();
  return unlockInFlight;
}

// --- Gestione password per host ----------------------------------------------

function setHostPassword(host: string, plaintext: string): void {
  if (!store || !sessionKey) return;
  store.hosts = store.hosts || {};
  store.hosts[host] = encrypt(sessionKey, plaintext);
  saveStore(store);
}

function acquireNewPassword(host: string, prompt: string): Promise<string | undefined> {
  // Un solo prompt "in volo" per host (evita doppi popup con connessioni parallele).
  const inFlight = pwInFlight.get(host);
  if (inFlight) return inFlight;
  const promise = (async () => {
    try {
      const pw = await inputPassword(prompt);
      if (pw === undefined || pw === '') return undefined;
      setHostPassword(host, pw);
      lockedHosts.delete(host);
      return pw;
    } finally {
      pwInFlight.delete(host);
    }
  })();
  pwInFlight.set(host, promise);
  return promise;
}

/**
 * Hook principale: rimpiazza promptForPassword dell'estensione.
 * @param promptStr es. "[host.example.com]: Password:"
 */
export async function askPassword(promptStr: string): Promise<string | undefined> {
  try {
    // Le passphrase di CHIAVE privata non sono di nostra competenza: passthrough.
    if (/passphrase/i.test(String(promptStr))) {
      return await inputPassword(promptStr);
    }
    const host = parseHost(promptStr);
    if (!host) return await inputPassword(promptStr); // prompt non riconosciuto: fallback

    const ok = await ensureUnlocked();
    if (!ok) return undefined; // master non fornita -> collegamento annullato

    if (lockedHosts.has(host)) {
      // Req.1: niente retry automatico. Chiediamo una password NUOVA (user-driven).
      return await acquireNewPassword(
        host,
        `${MSG}: la password per ${host} risulta errata o scaduta. Inserisci la nuova password (sara' salvata cifrata).`
      );
    }

    if (store.hosts && store.hosts[host]) {
      return decrypt(sessionKey as Buffer, store.hosts[host]);
    }

    // Host senza password memorizzata: la chiediamo una volta e la salviamo.
    return await acquireNewPassword(
      host,
      `${MSG}: inserisci la password per ${host} (sara' salvata cifrata con la tua passphrase master).`
    );
  } catch (e) {
    try {
      vscode().window.showErrorMessage(`${MSG} cred-manager: ` + (e && e.message));
    } catch (_e) {
      /* ignore */
    }
    // In caso di errore interno, fallback al prompt classico per non bloccare l'utente.
    try {
      return await inputPassword(String(promptStr));
    } catch (_e) {
      return undefined;
    }
  }
}

function isAuthFailure(errMsg: any): boolean {
  const m = String(errMsg || '').toLowerCase();
  if (!m) return false;
  if (m.includes('cancelled')) return false; // annullamento nostro/utente, non e' auth fallita
  return (
    m.includes('all configured authentication methods failed') ||
    m.includes('authentication') ||
    m.includes('permission denied') ||
    m.includes('auth fail')
  );
}

/**
 * Hook sul ramo di errore della connect(): decide se e' un fallimento di auth.
 */
export function onConnectError(host: string | undefined, err: any): void {
  try {
    const msg = err && (err.message || (err.toString ? err.toString() : err));
    if (!host || !isAuthFailure(msg)) return; // rete/altro: non bloccare la credenziale
    lockedHosts.add(host);
    const now = Date.now();
    const last = lastToastAt.get(host) || 0;
    if (now - last < TOAST_DEBOUNCE_MS) return; // debounce avvisi
    lastToastAt.set(host, now);
    vscode()
      .window.showErrorMessage(
        `${MSG}: autenticazione fallita per ${host}. La password potrebbe essere scaduta o errata.`,
        'Aggiorna password'
      )
      .then((sel: string | undefined) => {
        if (sel === 'Aggiorna password') runUpdatePassword(host);
      });
  } catch (_e) {
    /* mai propagare errori dall'hook */
  }
}

// --- Comandi ------------------------------------------------------------------

export async function runUpdatePassword(preHost?: string): Promise<void> {
  const v = vscode();
  const ok = await ensureUnlocked();
  if (!ok) return;
  let host = preHost;
  if (!host) {
    const known = Object.keys((store && store.hosts) || {});
    const OTHER = 'Altro host...';
    const items = known.length ? known.concat([OTHER]) : [OTHER];
    const pick = await v.window.showQuickPick(items, {
      placeHolder: "Seleziona l'host di cui aggiornare la password",
      ignoreFocusOut: true,
    });
    if (pick === undefined) return;
    if (pick === OTHER) {
      host = await v.window.showInputBox({
        prompt: 'Host (es. server.example.com)',
        ignoreFocusOut: true,
      });
      if (!host) return;
    } else {
      host = pick;
    }
  }
  const pw = await inputPassword(`Nuova password per ${host} (sara' salvata cifrata).`);
  if (pw === undefined || pw === '') return;
  setHostPassword(host as string, pw);
  lockedHosts.delete(host as string);
  v.window.showInformationMessage(`${MSG}: password aggiornata per ${host}.`);
}

export async function runResetCredentials(): Promise<void> {
  const v = vscode();
  const choice = await v.window.showWarningMessage(
    'Azzerare TUTTE le credenziali SFTP salvate (passphrase master + tutte le password)?\n' +
      'La configurazione host/profili (sftp.json) NON verra\' toccata.',
    { modal: true },
    'Azzera'
  );
  if (choice !== 'Azzera') return;
  deleteStore();
  sessionKey = null;
  store = null;
  lockedHosts.clear();
  lastToastAt.clear();
  v.window.showInformationMessage(
    `${MSG}: credenziali azzerate. Al prossimo collegamento imposterai una nuova passphrase master e le nuove password.`
  );
}

/**
 * Registra i comandi del credential manager. Da chiamare in activate() PRIMA
 * dell'eventuale return anticipato per workspace senza configurazione.
 */
export function activate(context: any): void {
  try {
    const v = vscode();
    const disp1 = v.commands.registerCommand(COMMAND_UPDATE_PASSWORD, () => runUpdatePassword());
    const disp2 = v.commands.registerCommand(COMMAND_RESET_CREDENTIALS, () => runResetCredentials());
    if (context && context.subscriptions) {
      context.subscriptions.push(disp1, disp2);
    }
  } catch (_e) {
    // se i comandi risultano gia' registrati (riattivazione), ignora
  }
}

// --- Superficie esposta ai soli unit test --------------------------------------

export const __test = {
  deriveKey,
  encrypt,
  decrypt,
  verifyKey,
  parseHost,
  isAuthFailure,
  VERIFIER_PLAINTEXT,
  storePath,
  legacyStorePath,
  loadStore,
  saveStore,
  deleteStore,
  ensureUnlocked,
  _state: () => ({
    hasKey: !!sessionKey,
    locked: Array.from(lockedHosts),
    hosts: store ? Object.keys(store.hosts || {}) : null,
  }),
  _reset: () => {
    sessionKey = null;
    store = null;
    lockedHosts.clear();
    lastToastAt.clear();
    unlockInFlight = null;
    pwInFlight.clear();
  },
  _setVscode: (mock: any) => {
    _vscode = mock;
  },
  _setStoreDirs: (dir: string, legacyDir: string) => {
    storeDir = dir;
    legacyStoreDir = legacyDir;
  },
};
