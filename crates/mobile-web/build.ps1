# Builds the phone app for the browser into target/mobile-web (index.html, the module and its
# WebAssembly). Needs: rustup target add wasm32-unknown-unknown
#                     cargo install wasm-bindgen-cli --version 0.2.130 --locked
# Then serve that folder, e.g.: python -m http.server 8080 --directory target/mobile-web
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot/../.."
Push-Location $root
try {
    cargo build -p vault-mobile-web --target wasm32-unknown-unknown --release
    wasm-bindgen --target web --no-typescript --out-dir target/mobile-web `
        target/wasm32-unknown-unknown/release/vault_mobile_web.wasm
    Copy-Item crates/mobile-web/index.html target/mobile-web/index.html
    Write-Host "Built target/mobile-web. Serve it: python -m http.server 8080 --directory target/mobile-web"
} finally {
    Pop-Location
}
