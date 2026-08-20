/* ============================================================
   auth.js — общая система входа + расшифровка контента

   Важно: здесь НЕТ пароля и НЕТ его хэша. Проверка происходит
   так: мы пытаемся расшифровать служебный файл verify.enc
   ключом, полученным из введённого пароля. Если пароль неверный —
   AES-GCM просто физически не даст расшифровать (встроенная
   проверка целостности), и никакого "правильного ответа" в коде
   для сравнения не существует.
   ============================================================ */

const AUTH = (() => {
    const SESSION_KEY = 'chait_key_v1';
    let configPromise = null;

    function getConfig() {
        if (!configPromise) {
            configPromise = fetch('crypto-config.json').then(r => r.json());
        }
        return configPromise;
    }

    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }

    function bytesToB64(bytes) {
        let bin = '';
        bytes.forEach(b => bin += String.fromCharCode(b));
        return btoa(bin);
    }

    function b64ToBytes(b64) {
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    }

    async function deriveKey(password, config) {
        const enc = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: hexToBytes(config.saltHex),
                iterations: config.iterations,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    async function decryptBuffer(key, buf) {
        const bytes = new Uint8Array(buf);
        const iv = bytes.slice(0, 12);
        const data = bytes.slice(12);
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    }

    async function tryUnlock(password) {
        const config = await getConfig();
        const key = await deriveKey(password, config);

        const resp = await fetch(config.verifyFile);
        if (!resp.ok) throw new Error('CONFIG_ERROR');
        const buf = await resp.arrayBuffer();

        let plainText;
        try {
            const plain = await decryptBuffer(key, buf);
            plainText = new TextDecoder().decode(plain);
        } catch (e) {
            throw new Error('WRONG_PASSWORD');
        }
        if (plainText !== 'OK') throw new Error('WRONG_PASSWORD');

        const raw = await crypto.subtle.exportKey('raw', key);
        sessionStorage.setItem(SESSION_KEY, bytesToB64(new Uint8Array(raw)));
        return key;
    }

    async function getStoredKey() {
        const b64 = sessionStorage.getItem(SESSION_KEY);
        if (!b64) return null;
        try {
            const raw = b64ToBytes(b64);
            return await crypto.subtle.importKey('raw', raw, 'AES-GCM', true, ['encrypt', 'decrypt']);
        } catch (e) {
            return null;
        }
    }

    function lock() {
        sessionStorage.removeItem(SESSION_KEY);
        location.reload();
    }

    return { getConfig, deriveKey, decryptBuffer, tryUnlock, getStoredKey, lock };
})();

/* ------------------------------------------------------------
   initGate(onUnlock) — вызывается на каждой странице.
   onUnlock(key) — необязательный callback: если странице нужно
   что-то расшифровать (например, галерее — фото), он получает
   готовый CryptoKey. Если onUnlock падает с ошибкой — форма
   остаётся на экране, контент не открывается.
   ------------------------------------------------------------ */
async function initGate(onUnlock) {
    const overlay = document.getElementById('auth-overlay');
    const content = document.getElementById('page-content');
    const form = document.getElementById('auth-form');
    const input = document.getElementById('auth-password');
    const errorEl = document.getElementById('auth-error');
    const logoutBtn = document.getElementById('auth-logout');

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => AUTH.lock());
    }

    async function reveal(key) {
        if (onUnlock) await onUnlock(key);
        overlay.hidden = true;
        content.hidden = false;
        if (logoutBtn) logoutBtn.hidden = false;
    }

    const stored = await AUTH.getStoredKey();
    if (stored) {
        try {
            await reveal(stored);
            return;
        } catch (e) {
            sessionStorage.removeItem('chait_key_v1');
            // ключ оказался нерабочим — упадём в обычный сценарий входа ниже
        }
    }

    overlay.hidden = false;
    content.hidden = true;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        errorEl.textContent = '';
        const submitBtn = form.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        try {
            const key = await AUTH.tryUnlock(input.value);
            await reveal(key);
        } catch (err) {
            if (err && err.message === 'WRONG_PASSWORD') {
                errorEl.textContent = 'Неверный пароль. Попробуйте ещё раз.';
            } else {
                errorEl.textContent = 'Ошибка загрузки. Обновите страницу и попробуйте снова.';
                console.error(err);
            }
            input.value = '';
            input.focus();
        } finally {
            submitBtn.disabled = false;
        }
    });
}