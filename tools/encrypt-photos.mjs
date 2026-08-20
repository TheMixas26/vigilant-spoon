#!/usr/bin/env node
/**
 * encrypt-photos.mjs
 * ------------------------------------------------------------
 * Шифрует все фото из photos_src/ в photos/*.enc с помощью
 * AES-256-GCM. Ключ получается из пароля через PBKDF2 — того
 * же пароля, что потом будет вводить Чай на сайте.
 *
 * ЗАПУСК (из корня проекта, там где лежит index.html):
 *   node tools/encrypt-photos.mjs
 * Скрипт спросит пароль в терминале.
 *
 * Без интерактивного ввода (например, в CI):
 *   CHAIT_PASSWORD="моя фраза" node tools/encrypt-photos.mjs
 *
 * ПЕРЕД ЗАПУСКОМ:
 *   1. Создай папку photos_src/ рядом с index.html
 *   2. Положи туда фото (.jpg, .jpeg, .png, .gif, .webp)
 *   3. (необязательно) создай photos_src/captions.json вида:
 *        { "photo1.jpeg": "подпись к фото" }
 *
 * ВАЖНО:
 *   - photos_src/ НЕ должна попадать в git (см. .gitignore) —
 *     это оригиналы без шифрования, только для локальной сборки.
 *   - Перезапускай скрипт каждый раз, когда добавляешь новые
 *     фото — он пересобирает всю галерею из photos_src/ целиком.
 *   - crypto-config.json создаётся один раз и переиспользуется:
 *     не удаляй его, иначе старые фото перестанут расшифровываться.
 */
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync } from 'node:fs';
import { randomBytes, createCipheriv, pbkdf2Sync } from 'node:crypto';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const CONFIG_PATH = path.join(ROOT, 'crypto-config.json');
const SRC_DIR = path.join(ROOT, 'photos_src');
const OUT_DIR = path.join(ROOT, 'photos');

const MIME_TYPES = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.png': 'image/png', '.gif': 'image/gif',
    '.webp': 'image/webp'
};

function loadOrCreateConfig() {
    if (existsSync(CONFIG_PATH)) {
        return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
    }
    const config = {
        saltHex: randomBytes(16).toString('hex'), // соль НЕ секретна, это нормально
        iterations: 300000,
        verifyFile: 'verify.enc'
    };
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
    console.log('Создан новый crypto-config.json (соль сгенерирована один раз, дальше переиспользуется).');
    return config;
}

function askPassword() {
    if (process.env.CHAIT_PASSWORD) return Promise.resolve(process.env.CHAIT_PASSWORD);
    return new Promise((resolve) => {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        rl.question('Пароль (тот же, что будет вводить Чай на сайте): ', (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

function deriveKey(password, config) {
    return pbkdf2Sync(password, Buffer.from(config.saltHex, 'hex'), config.iterations, 32, 'sha256');
}

// Формат файла: iv(12 байт) + ciphertext + tag(16 байт) —
// именно так это ожидает SubtleCrypto в браузере.
function encryptBuffer(key, buf) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(buf), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, ciphertext, tag]);
}

function loadCaptions() {
    const p = path.join(SRC_DIR, 'captions.json');
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf8'));
    return {};
}

async function main() {
    if (!existsSync(SRC_DIR)) {
        console.error(`Не найдена папка ${SRC_DIR}.\nСоздай её и положи туда фото перед запуском.`);
        process.exit(1);
    }
    mkdirSync(OUT_DIR, { recursive: true });

    const config = loadOrCreateConfig();
    const password = await askPassword();
    if (!password) {
        console.error('Пароль не может быть пустым.');
        process.exit(1);
    }
    const key = deriveKey(password, config);

    // verify.enc — шифрует известную строку "OK".
    // Именно по нему сайт проверяет, правильный ли введён пароль.
    const verifyBuf = encryptBuffer(key, Buffer.from('OK', 'utf8'));
    writeFileSync(path.join(ROOT, config.verifyFile), verifyBuf);

    const captions = loadCaptions();
    const files = readdirSync(SRC_DIR).filter(f => {
        const ext = path.extname(f).toLowerCase();
        return MIME_TYPES[ext];
    });

    if (files.length === 0) {
        console.warn('В photos_src/ не найдено ни одного изображения (.jpg/.jpeg/.png/.gif/.webp).');
    }

    const manifest = [];
    for (const file of files) {
        const ext = path.extname(file).toLowerCase();
        const mime = MIME_TYPES[ext];
        const buf = readFileSync(path.join(SRC_DIR, file));
        const encBuf = encryptBuffer(key, buf);
        const outName = file + '.enc';
        writeFileSync(path.join(OUT_DIR, outName), encBuf);
        manifest.push({ file: outName, mime, alt: captions[file] || '' });
        console.log(`Зашифровано: ${file} -> photos/${outName}`);
    }

    writeFileSync(path.join(OUT_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2));

    console.log(`\nГотово! Зашифровано файлов: ${files.length}.`);
    console.log('Закоммить: crypto-config.json, verify.enc, photos/*.enc, photos/manifest.json');
    console.log('НЕ коммить: photos_src/ — там лежат оригиналы без шифрования!');
}

main();
