<#
.SYNOPSIS
    Impacchetta l'estensione come .vsix "lean" (node_modules di sole produzione).

.DESCRIPTION
    Il bundle webpack marca 'ssh2' come external, quindi node_modules DEVE essere
    incluso nel .vsix — ma solo con le dipendenze di produzione (come il pacchetto
    originale pubblicato sul Marketplace). Flusso:
      1. npm ci                (dipendenze esatte dal lockfile)
      2. npm run compile       (bundle webpack in dist/)
      3. npm prune --omit=dev  (node_modules ridotto alle prod deps)
      4. vsce package          (con 'vscode:prepublish' temporaneamente rimosso:
                                vsce lo rilancerebbe ma webpack non c'è più dopo il prune)
      5. ripristino package.json e, salvo -KeepProd, delle dev deps (npm ci)

    Richiede @vscode/vsce installato GLOBALMENTE (npm install -g @vscode/vsce).
    Non installarlo nel progetto: altera l'hoisting di node_modules e cambia il bundle.

.PARAMETER OutDir
    Cartella di destinazione del .vsix. Default: radice del repo.

.PARAMETER KeepProd
    Non ripristinare le dev dependencies alla fine (utile in CI).
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [switch]$KeepProd
)

# NB: niente $ErrorActionPreference='Stop': in PowerShell 5.1 i warning npm su
# stderr diventerebbero errori terminanti. Gli errori reali sono gestiti con
# i check espliciti su $LASTEXITCODE dopo ogni passo.
$ErrorActionPreference = 'Continue'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root
if (-not $OutDir) { $OutDir = $root }

if (-not (Get-Command vsce -ErrorAction SilentlyContinue)) {
    throw "vsce non trovato. Installa con: npm install -g @vscode/vsce"
}

npm ci --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw "npm ci fallito" }

npm run compile
if ($LASTEXITCODE -ne 0) { throw "compile fallito" }

npm prune --omit=dev --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw "npm prune fallito" }

$pkgPath = Join-Path $root 'package.json'
$pkgRaw = [IO.File]::ReadAllText($pkgPath)
$name = node -p "require('./package.json').name"
$version = node -p "require('./package.json').version"
$out = Join-Path $OutDir "$name-$version.vsix"

try {
    node -e "const fs=require('fs');const p=require('./package.json');delete p.scripts['vscode:prepublish'];fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n')"
    vsce package --dependencies --out $out
    if ($LASTEXITCODE -ne 0) { throw "vsce package fallito" }
}
finally {
    [IO.File]::WriteAllText($pkgPath, $pkgRaw)
}

if (-not $KeepProd) {
    npm ci --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw "npm ci (ripristino dev deps) fallito" }
}

Write-Host ""
Write-Host "VSIX creato: $out" -ForegroundColor Green
