#!/usr/bin/env node
/**
 * 独立命令行程序（纯 Node.js 标准库实现，零第三方依赖）：
 *   1. creds : 基于浏览器扩展机制获取凭证（首次打印登录 URL，提示粘贴 Cookie 并提取 page-config/csrfToken）
 *   2. serve : 通过环境变量/JSON 文件读取凭证，暴露为标准 OpenAI Compatible API（支持自动刷新 csrfToken）
 */

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_CREDS_FILE = path.resolve(__dirname, './credentials.json');
const DEFAULT_SESSIONS_FILE = path.resolve(process.cwd(), './sessions.json');
const EXT_VERSION = '1.0.13657.0';
const EXT_REFRESH_INTERVAL_SEC = 50 * 60; // 对齐 ext/background.js 每 50 分钟刷新一次

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let DEBUG_ENABLED = ['1', 'true', 'yes'].includes(String(process.env.QUICK_DEBUG || '').toLowerCase());

function logInfo(tag, msg, extra) {
  const ts = new Date().toISOString();
  const suffix = extra !== undefined ? ` ${typeof extra === 'string' ? extra : JSON.stringify(extra)}` : '';
  process.stderr.write(`[${ts}] [${tag}] ${msg}${suffix}\n`);
}

function logDebug(tag, msg, extra) {
  if (!DEBUG_ENABLED) return;
  logInfo(`${tag}:DEBUG`, msg, extra);
}

// ---------------------------------------------------------------------------
// 轻量 AWS EventStream & CBOR 编解码（纯标准库）
// ---------------------------------------------------------------------------

const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC32_TABLE[i] = c >>> 0;
}
function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function esEncode(headers, payload) {
  const chunks = Object.entries(headers).map(([k, v]) => {
    const n = encoder.encode(k);
    const val = encoder.encode(v);
    const out = new Uint8Array(1 + n.length + 1 + 2 + val.length);
    out[0] = n.length;
    out.set(n, 1);
    out[1 + n.length] = 7;
    new DataView(out.buffer).setUint16(1 + n.length + 1, val.length, false);
    out.set(val, 1 + n.length + 3);
    return out;
  });
  const headersLen = chunks.reduce((s, c) => s + c.length, 0);
  const totalLen = 12 + headersLen + payload.length + 4;
  const buf = new Uint8Array(totalLen);
  const view = new DataView(buf.buffer);
  view.setUint32(0, totalLen, false);
  view.setUint32(4, headersLen, false);
  view.setUint32(8, crc32(buf.subarray(0, 8)), false);
  let off = 12;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.length;
  }
  buf.set(payload, off);
  view.setUint32(totalLen - 4, crc32(buf.subarray(0, totalLen - 4)), false);
  return buf;
}

function esDecodeFrame(frame) {
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const totalLen = view.getUint32(0, false);
  const headersLen = view.getUint32(4, false);
  const headers = {};
  let pos = 12;
  const headersEnd = 12 + headersLen;
  while (pos < headersEnd) {
    const nLen = frame[pos++];
    const name = decoder.decode(frame.subarray(pos, pos + nLen));
    pos += nLen;
    const type = frame[pos++];
    if (type === 7) {
      const vLen = view.getUint16(pos, false);
      pos += 2;
      headers[name] = decoder.decode(frame.subarray(pos, pos + vLen));
      pos += vLen;
    } else {
      break;
    }
  }
  return { headers, payload: frame.subarray(headersEnd, totalLen - 4) };
}

function cborEncodeHead(major, n, out) {
  const mt = major << 5;
  if (n < 24) out.push(mt | n);
  else if (n < 0x100) out.push(mt | 24, n);
  else if (n < 0x10000) out.push(mt | 25, (n >> 8) & 0xff, n & 0xff);
  else out.push(mt | 26, (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
}
function cborEnc(obj, out) {
  if (obj === null || obj === undefined) out.push(0xf6);
  else if (typeof obj === 'boolean') out.push(obj ? 0xf5 : 0xf4);
  else if (typeof obj === 'number') cborEncodeHead(obj >= 0 ? 0 : 1, obj >= 0 ? obj : -1 - obj, out);
  else if (obj instanceof Uint8Array) {
    cborEncodeHead(2, obj.length, out);
    for (let i = 0; i < obj.length; i++) out.push(obj[i]);
  } else if (typeof obj === 'string') {
    const b = encoder.encode(obj);
    cborEncodeHead(3, b.length, out);
    for (let i = 0; i < b.length; i++) out.push(b[i]);
  } else if (Array.isArray(obj)) {
    cborEncodeHead(4, obj.length, out);
    for (const item of obj) cborEnc(item, out);
  } else if (typeof obj === 'object') {
    const entries = Object.entries(obj);
    cborEncodeHead(5, entries.length, out);
    for (const [k, v] of entries) {
      cborEnc(k, out);
      cborEnc(v, out);
    }
  }
}
function cborDecode(data) {
  function readLen(ai, i) {
    let len = ai;
    if (ai === 24) len = data[i++];
    else if (ai === 25) { len = (data[i] << 8) | data[i + 1]; i += 2; }
    else if (ai === 26) {
      len = ((data[i] << 24) >>> 0) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3];
      i += 4;
    } else if (ai === 27) {
      const hi = ((data[i] << 24) >>> 0) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3];
      const lo = ((data[i + 4] << 24) >>> 0) + (data[i + 5] << 16) + (data[i + 6] << 8) + data[i + 7];
      len = hi * 4294967296 + lo;
      i += 8;
    }
    return [len, i];
  }
  function dec(i) {
    const ib = data[i++];
    const major = ib >> 5;
    const ai = ib & 0x1f;
    if (major === 6) {
      [, i] = readLen(ai, i);
      return dec(i);
    }
    if (major === 7) {
      if (ai === 20) return [false, i];
      if (ai === 21) return [true, i];
      if (ai === 22 || ai === 23) return [null, i];
      if (ai === 26) {
        const dv = new DataView(data.buffer, data.byteOffset + i, 4);
        return [dv.getFloat32(0), i + 4];
      }
      if (ai === 27) {
        const dv = new DataView(data.buffer, data.byteOffset + i, 8);
        return [dv.getFloat64(0), i + 8];
      }
      throw new Error(`Unsupported CBOR simple: ${ai}`);
    }
    if (ai === 31) {
      if (major === 2) {
        const chunks = [];
        let total = 0;
        while (data[i] !== 0xff) {
          const [chunk, next] = dec(i);
          chunks.push(chunk);
          total += chunk.length;
          i = next;
        }
        const merged = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) { merged.set(c, off); off += c.length; }
        return [merged, i + 1];
      }
      if (major === 3) {
        let out = '';
        while (data[i] !== 0xff) {
          const [chunk, next] = dec(i);
          out += chunk;
          i = next;
        }
        return [out, i + 1];
      }
      if (major === 4) {
        const arr = [];
        while (data[i] !== 0xff) {
          const [v, next] = dec(i);
          arr.push(v);
          i = next;
        }
        return [arr, i + 1];
      }
      if (major === 5) {
        const obj = {};
        while (data[i] !== 0xff) {
          const [key, nk] = dec(i);
          const [v, nv] = dec(nk);
          obj[key] = v;
          i = nv;
        }
        return [obj, i + 1];
      }
      throw new Error(`Unsupported CBOR indefinite major: ${major}`);
    }
    let len;
    [len, i] = readLen(ai, i);
    if (major === 0) return [len, i];
    if (major === 1) return [-1 - len, i];
    if (major === 2) return [data.subarray(i, i + len), i + len];
    if (major === 3) return [decoder.decode(data.subarray(i, i + len)), i + len];
    if (major === 4) {
      const arr = [];
      for (let k = 0; k < len; k++) { const [v, n] = dec(i); arr.push(v); i = n; }
      return [arr, i];
    }
    if (major === 5) {
      const obj = {};
      for (let k = 0; k < len; k++) { const [key, nk] = dec(i); const [v, nv] = dec(nk); obj[key] = v; i = nv; }
      return [obj, i];
    }
    throw new Error(`Unsupported CBOR major: ${major}`);
  }
  return dec(0)[0];
}

function encodeAidpInputEvent(obj) {
  const b64 = Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
  return encoder.encode(JSON.stringify({ eventType: 'rawInputEvent', payload: { payload: b64 } }));
}
function decodeAidpOutputEvent(bytes) {
  const es = esDecodeFrame(bytes);
  if (es.headers[':event-type'] !== 'rawOutputEvent' || !es.payload?.length) return null;
  const wrapper = JSON.parse(decoder.decode(es.payload));
  if (typeof wrapper?.payload !== 'string') return null;
  return JSON.parse(Buffer.from(wrapper.payload, 'base64').toString('utf8'));
}

function encodeGatewayFrame(obj) {
  const out = [];
  cborEnc({ payload: encoder.encode(JSON.stringify(obj)) }, out);
  return esEncode({ ':message-type': 'event', ':event-type': 'input' }, new Uint8Array(out));
}
function decodeGatewayFrame(bytes) {
  const { payload } = esDecodeFrame(bytes);
  if (!payload?.length) return null;
  const decoded = cborDecode(payload);
  if (decoded?.payload instanceof Uint8Array) {
    return JSON.parse(decoder.decode(decoded.payload));
  }
  return decoded;
}

// 浏览器扩展 (wsproxy-protocol=rpc-v2-cbor) 专用编解码（对齐 ext/AppContext.js）
function encodeExtensionFrame(obj) {
  const out = [];
  cborEnc({ payload: encoder.encode(JSON.stringify(obj)) }, out);
  return esEncode(
    {
      ':event-type': 'rawInputEvent',
      ':content-type': 'application/cbor',
      ':message-type': 'event',
    },
    new Uint8Array(out)
  );
}

function decodeExtensionFrame(bytes) {
  const { headers, payload } = esDecodeFrame(bytes);
  const msgType = headers[':message-type'] || '';
  const eventType = headers[':event-type'] || headers[':exception-type'] || '';
  const contentType = headers[':content-type'] || '';

  if (msgType === 'error') {
    const code = headers[':error-code'] || 'Error';
    const message = headers[':error-message'] || '';
    throw new Error(`Quick WS error [${code}]: ${message}`);
  }
  if (eventType === 'initial-response' || !eventType) {
    return null;
  }

  let bodyObj = {};
  if (payload && payload.length > 0) {
    if (contentType.includes('cbor')) {
      bodyObj = cborDecode(payload);
    } else {
      const txt = decoder.decode(payload);
      bodyObj = txt ? JSON.parse(txt) : {};
    }
  }

  if (msgType === 'exception') {
    throw new Error(`Quick WS exception [${eventType}]: ${JSON.stringify(bodyObj)}`);
  }

  if (bodyObj?.payload instanceof Uint8Array) {
    return JSON.parse(decoder.decode(bodyObj.payload));
  }
  if (typeof bodyObj?.payload === 'string') {
    try {
      return JSON.parse(Buffer.from(bodyObj.payload, 'base64').toString('utf8'));
    } catch {
      return JSON.parse(bodyObj.payload);
    }
  }
  return bodyObj;
}

// ---------------------------------------------------------------------------
// 1. 浏览器扩展机制：打印登录 URL、读取 Cookie、拉取 /sn/start 解析 page-config
// ---------------------------------------------------------------------------

function buildExtensionLoginUrl({ region = 'us-east-1', accountAlias = '', loginMode = 'social' } = {}) {
  if (loginMode === 'enterprise' || accountAlias) {
    const base = `https://${region}.quicksight.aws.amazon.com/sn/qbs-chrome-extension-redirect?qs-signin-user-auth=false`;
    return accountAlias ? `${base}&directory_alias=${encodeURIComponent(accountAlias)}` : base;
  }
  return 'https://profile.aws.amazon.com/#/discovery/quicksight?autologin=true&discovery_state=sn%2Fqbs-chrome-extension-redirect';
}

function normalizeCookieInput(raw) {
  let s = String(raw || '').trim();
  if (!s) return '';
  if (/^(set-)?cookie\s*:/i.test(s)) {
    s = s.replace(/^(set-)?cookie\s*:/i, '').trim();
  }
  // 去掉 Set-Cookie 属性（Domain / Path / Expires / Max-Age / HttpOnly / Secure / SameSite / Priority）
  const attrNames = new Set([
    'domain', 'path', 'expires', 'max-age', 'httponly', 'secure', 'samesite', 'priority', 'partitioned',
  ]);
  const pairs = [];
  for (const part of s.split(/[\r\n;]+/)) {
    const item = part.trim();
    if (!item) continue;
    const eq = item.indexOf('=');
    const key = eq > 0 ? item.slice(0, eq).trim() : item;
    if (attrNames.has(key.toLowerCase())) continue;
    if (eq > 0) {
      pairs.push(`${key}=${item.slice(eq + 1).trim()}`);
    }
  }
  return pairs.join('; ');
}

function extractAliasFromRawInput(raw) {
  const m = String(raw || '').match(/\/sn\/account\/([a-zA-Z0-9_-]+)/);
  if (m) return m[1];
  const m2 = String(raw || '').match(/qs-directory-alias=([a-zA-Z0-9_-]+)/);
  return m2 ? m2[1] : '';
}

function mergeCookies(existingCookie, setCookieHeaders) {
  const jar = new Map();
  for (const part of String(existingCookie || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k) jar.set(k, v);
    }
  }
  for (const sc of setCookieHeaders || []) {
    const first = String(sc).split(';')[0];
    const idx = first.indexOf('=');
    if (idx > 0) {
      const k = first.slice(0, idx).trim();
      const v = first.slice(idx + 1).trim();
      if (k) jar.set(k, v);
    }
  }
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

function extractScriptJsonById(html, id) {
  const re = new RegExp(`<([a-z0-9]+)\\b[^>]*\\bid\\s*=\\s*["']${id}["'][^>]*>\\s*([\\s\\S]*?)\\s*</\\1>`, 'i');
  const m = html.match(re);
  if (!m) return null;
  const decoded = m[2]
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
  return JSON.parse(decoded);
}

function getExtensionPathPrefix(subPath, accountAlias) {
  const clean = subPath.replace(/^\/+/, '');
  return accountAlias ? `/sn/account/${encodeURIComponent(accountAlias)}/${clean}` : `/sn/${clean}`;
}

async function fetchExtensionConfigWithCookie({ cookie, region = 'us-east-1', accountAlias = '', endpointOverride = '' }) {
  const cleanCookie = normalizeCookieInput(cookie);
  if (!cleanCookie) {
    throw new Error('Cookie is empty.');
  }

  const resolvedAlias = accountAlias || extractAliasFromRawInput(cookie);
  const isQuickAwsCom = !endpointOverride && (cleanCookie.includes('aws-ds-access-token=') || String(cookie).includes('quick.aws.com'));
  const baseEndpoint = endpointOverride
    ? endpointOverride.replace(/\/+$/, '')
    : isQuickAwsCom
    ? 'https://quick.aws.com'
    : `https://${region}.quicksight.aws.amazon.com`;

  const startPath = getExtensionPathPrefix('start', resolvedAlias);
  const url = `${baseEndpoint}${startPath}?state=hashArgs%23`;

  let currentUrl = url;
  let mergedCookie = cleanCookie;
  let resp;
  // 若同域或跳转到另一区域的 quicksight.aws.amazon.com / quick.aws.com，自动携带 Cookie 跟随（最多 4 跳）
  for (let hop = 0; hop < 4; hop++) {
    resp = await fetch(currentUrl, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        Cookie: mergedCookie,
        'x-amzn-qs-src': `extn-chrome; ${EXT_VERSION}`,
        Accept: 'text/html,application/xhtml+xml',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      },
    });

    const setCookies = typeof resp.headers.getSetCookie === 'function'
      ? resp.headers.getSetCookie()
      : [];
    mergedCookie = mergeCookies(mergedCookie, setCookies);

    if (resp.status >= 300 && resp.status < 400) {
      const loc = resp.headers.get('location') || '';
      let nextUrl;
      try {
        nextUrl = new URL(loc, currentUrl);
      } catch {
        throw new Error(`Session expired or unauthenticated (HTTP ${resp.status} -> ${loc}). Please sign in again.`);
      }
      const isQuickHost =
        nextUrl.hostname.endsWith('.quicksight.aws.amazon.com') ||
        nextUrl.hostname === 'quick.aws.com' ||
        nextUrl.hostname.endsWith('.quick.aws.com') ||
        nextUrl.hostname === '127.0.0.1';
      if (isQuickHost && !nextUrl.pathname.includes('signin')) {
        if (!nextUrl.pathname.endsWith('/sn') && !nextUrl.searchParams.has('state')) {
          nextUrl.searchParams.set('state', 'hashArgs#');
        }
        currentUrl = nextUrl.toString();
        continue;
      }
      throw new Error(
        `Session expired or missing HttpOnly auth cookies (HTTP ${resp.status} -> ${loc}).\n` +
          `请确保从浏览器 DevTools -> Network -> Request Headers 中复制完整的 Cookie 请求头（不要使用 document.cookie）。`
      );
    }
    break;
  }

  if (!resp.ok) {
    throw new Error(`Failed to fetch ${currentUrl}: HTTP ${resp.status}`);
  }

  const effectiveBaseEndpoint = new URL(currentUrl).origin;

  const html = await resp.text();
  const pageConfig = extractScriptJsonById(html, 'page-config');
  const clientConfig = extractScriptJsonById(html, 'client-config');

  if (!pageConfig?.csrf) {
    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : '(no title)';
    const scriptIds = [...html.matchAll(/<script[^>]+id=["']([^"']+)["']/gi)].map((m) => m[1]);
    throw new Error(
      `Could not find page-config csrfToken in response HTML.\n` +
        `  URL: ${currentUrl} (HTTP ${resp.status})\n` +
        `  Title: ${title}\n` +
        `  Script IDs: ${scriptIds.length > 0 ? scriptIds.join(', ') : '(none)'}\n` +
        `  Preview: ${html.replace(/\s+/g, ' ').slice(0, 260)}`
    );
  }

  const resolvedRegion = clientConfig?.regionInfo?.currentRegion || region;
  const available = clientConfig?.regionInfo?.availableRegions || [];
  const regionEntry = available.find((r) => r.id === resolvedRegion);
  const serviceEndpoint = regionEntry?.url
    ? new URL(regionEntry.url).origin
    : effectiveBaseEndpoint;

  return {
    provider: 'extension',
    cookie: mergedCookie,
    csrfToken: pageConfig.csrf,
    accountId: pageConfig.awsAccountId || '',
    userId: pageConfig.quickSightUserId || '',
    accountAlias: pageConfig.accountAlias || accountAlias || '',
    region: resolvedRegion,
    serviceEndpoint,
    wsHost: new URL(serviceEndpoint).host,
    tenantUrl: serviceEndpoint,
    usableUntil: Math.floor(Date.now() / 1000) + EXT_REFRESH_INTERVAL_SEC,
  };
}

async function promptForCookieInteractive(loginUrl) {
  process.stderr.write('\n=== AWS Quick 浏览器扩展登录指引 ===\n');
  process.stderr.write(`1. 请在浏览器中打开以下登录地址完成登录：\n   ${loginUrl}\n`);
  process.stderr.write('2. 登录完成后进入 Quick 页面，按 F12 打开 DevTools -> Network 面板，\n');
  process.stderr.write('   选中发往 quick.aws.com/sn/account/... 或 quicksight.aws.amazon.com/sn/account/... 的请求，\n');
  process.stderr.write('   复制 Request Headers 中完整的 cookie 请求头值（不要只复制单条 Set-Cookie，也不要用 document.cookie）。\n');
  process.stderr.write('3. 请粘贴 Cookie 并按回车确认（支持超长 Cookie）：\n> ');

  const raw = await new Promise((resolve) => {
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    // 在 TTY 下使用 raw mode 读取，绕过 macOS 1024 字节规范模式行长度限制
    if (process.stdin.isTTY && typeof process.stdin.setRawMode === 'function') {
      let buf = '';
      const wasRaw = process.stdin.isRaw;
      process.stdin.setRawMode(true);

      const finish = () => {
        process.stdin.removeListener('data', onData);
        try {
          process.stdin.setRawMode(Boolean(wasRaw));
        } catch { /* ignore */ }
        process.stdin.pause();
        process.stdin.unref?.();
        process.stderr.write('\n');
        resolve(buf);
      };

      const onData = (chunk) => {
        for (let i = 0; i < chunk.length; i++) {
          const ch = chunk[i];
          if (ch === '\u0003') {
            // Ctrl+C
            try { process.stdin.setRawMode(Boolean(wasRaw)); } catch {}
            process.stderr.write('\nCancelled.\n');
            process.exit(130);
          }
          if (ch === '\r' || ch === '\n') {
            // 仅在已有内容时回车提交，忽略粘贴前导换行
            if (buf.trim().length > 0) {
              finish();
              return;
            }
          } else if (ch === '\u007f' || ch === '\b') {
            if (buf.length > 0) {
              buf = buf.slice(0, -1);
            }
          } else {
            buf += ch;
          }
        }
      };

      process.stdin.on('data', onData);
      return;
    }

    // 非 TTY 管道模式
    let buf = '';
    const onData = (chunk) => {
      buf += chunk;
      const idx = buf.search(/[\r\n]/);
      if (idx !== -1 && buf.slice(0, idx).trim().length > 0) {
        process.stdin.removeListener('data', onData);
        process.stdin.removeListener('end', onEnd);
        process.stdin.pause();
        process.stdin.unref?.();
        resolve(buf.slice(0, idx));
      }
    };
    const onEnd = () => {
      process.stdin.removeListener('data', onData);
      resolve(buf);
    };
    process.stdin.on('data', onData);
    process.stdin.on('end', onEnd);
  });

  const normalized = normalizeCookieInput(raw);
  process.stderr.write(`[quick-openai] Cookie received (${normalized.length} chars), verifying via /sn/start...\n`);
  return raw;
}

function resolveOutpostId(flags = {}) {
  const explicit = flags['outpost-id'] || process.env.QUICK_OUTPOST_ID;
  if (explicit) return explicit.trim();

  const qwDir = path.join(os.homedir(), '.quickwork');
  try {
    const profilesPath = path.join(qwDir, 'profiles.json');
    if (fs.existsSync(profilesPath)) {
      const profiles = JSON.parse(fs.readFileSync(profilesPath, 'utf8'));
      const active = profiles?.last_active;
      if (active) {
        const devPath = path.join(qwDir, 'profiles', active, 'device_id');
        if (fs.existsSync(devPath)) {
          const id = fs.readFileSync(devPath, 'utf8').trim();
          if (id) return id;
        }
      }
    }
  } catch {
    // ignore
  }

  try {
    const rootDevPath = path.join(qwDir, 'device_id');
    if (fs.existsSync(rootDevPath)) {
      const id = fs.readFileSync(rootDevPath, 'utf8').trim();
      if (id) return id;
    }
  } catch {
    // ignore
  }
  return '';
}

function resolveCredsFilePath(flags) {
  return path.resolve(flags['creds-file'] || DEFAULT_CREDS_FILE);
}

function loadCredsFromFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);
    return data && typeof data === 'object' ? data : null;
  } catch {
    return null;
  }
}

function saveCredsToFile(filePath, creds) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const payload = {
    provider: creds.provider || 'extension',
    cookie: creds.cookie || '',
    csrfToken: creds.csrfToken || '',
    serviceEndpoint: creds.serviceEndpoint || creds.tenantUrl || '',
    wsHost: creds.wsHost || '',
    tenantUrl: creds.tenantUrl || creds.serviceEndpoint || '',
    accountId: creds.accountId || '',
    accountAlias: creds.accountAlias || '',
    userId: creds.userId || '',
    region: creds.region || 'us-east-1',
    usableUntil: creds.usableUntil ?? null,
    updatedAt: new Date().toISOString(),
  };
  const tmpPath = path.join(dir, `.credentials-${crypto.randomBytes(6).toString('hex')}.tmp`);
  fs.writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
}

function shellEscape(val) {
  return `'${String(val).replace(/'/g, `'\\''`)}'`;
}

async function runCredsCommand(flags) {
  const format = (flags.format || 'json').toLowerCase();
  const region = flags.region || 'us-east-1';
  const accountAlias = flags.alias || '';
  const endpointOverride = flags.endpoint || '';
  const credsFile = resolveCredsFilePath(flags);
  const existing = loadCredsFromFile(credsFile);

  let rawInput = '';
  let cookie = normalizeCookieInput(flags.cookie || '');
  if (flags.cookie) rawInput = flags.cookie;
  if (!cookie && existing?.cookie && flags.relogin !== 'true') {
    cookie = existing.cookie;
  }

  const loginUrl = buildExtensionLoginUrl({ region, accountAlias });
  if (!cookie) {
    rawInput = await promptForCookieInteractive(loginUrl);
    cookie = normalizeCookieInput(rawInput);
  }

  const detectedAlias = accountAlias || extractAliasFromRawInput(rawInput);

  let creds;
  try {
    creds = await fetchExtensionConfigWithCookie({ cookie, region, accountAlias: detectedAlias, endpointOverride });
  } catch (err) {
    // 若已有缓存 cookie 失效，重新打印登录 URL 引导输入新 Cookie
    if (existing?.cookie && !flags.cookie && flags.relogin !== 'true') {
      process.stderr.write(`[quick-openai] Cached cookie invalid (${err.message}).\n`);
      rawInput = await promptForCookieInteractive(loginUrl);
      cookie = normalizeCookieInput(rawInput);
      const retryAlias = accountAlias || extractAliasFromRawInput(rawInput);
      creds = await fetchExtensionConfigWithCookie({ cookie, region, accountAlias: retryAlias, endpointOverride });
    } else {
      throw err;
    }
  }

  if (flags['no-save'] !== 'true') {
    saveCredsToFile(credsFile, creds);
    process.stderr.write(`[quick-openai] Credentials saved to ${credsFile}\n`);
  }

  if (format === 'json') {
    process.stdout.write(`${JSON.stringify(creds, null, 2)}\n`);
  }
}

// ---------------------------------------------------------------------------
// 2. 将 Quick WS 暴露为标准 OpenAI Compatible API (serve)
// ---------------------------------------------------------------------------

const TOOL_CALL_OPEN = '<qw_tool_call>';
const TOOL_CALL_CLOSE = '</qw_tool_call>';
// Quick WS 原始帧限制 64KB，单条安全文本上限设为 42KB；超出时自动拆分为多条消息发送
const MAX_QUICK_PROMPT_BYTES = 42 * 1024;
const MAX_PROMPT_CHUNKS = 8;

function splitUtf8ByMaxBytes(str, maxBytes) {
  if (Buffer.byteLength(str, 'utf8') <= maxBytes) return [str];
  const chunks = [];
  let remaining = str;
  while (Buffer.byteLength(remaining, 'utf8') > maxBytes) {
    const buf = Buffer.from(remaining, 'utf8');
    let cut = maxBytes;
    // 避免切断多字节 UTF-8 字符（续字节特征 10xxxxxx）
    while (cut > 0 && (buf[cut] & 0xc0) === 0x80) cut--;
    if (cut === 0) cut = maxBytes;
    let piece = buf.subarray(0, cut).toString('utf8');
    // 优先在换行处切分，避免截断代码行或 JSON
    const lastNl = piece.lastIndexOf('\n');
    if (lastNl > piece.length * 0.6) {
      piece = piece.slice(0, lastNl + 1);
    }
    chunks.push(piece);
    remaining = remaining.slice(piece.length);
  }
  if (remaining) chunks.push(remaining);
  return chunks;
}

function truncateUtf8Bytes(str, maxBytes) {
  if (Buffer.byteLength(str, 'utf8') <= maxBytes) return str;
  const buf = Buffer.from(str, 'utf8');
  // 留出截断提示语空间
  const notice = '\n...[truncated due to 64KB message limit]...';
  const keep = Math.max(0, maxBytes - Buffer.byteLength(notice, 'utf8'));
  return buf.subarray(0, keep).toString('utf8') + notice;
}

function formatMessagesForQuick(messages, tools, toolChoice, { startIndex = 0 } = {}) {
  const parts = [];
  const isIncremental = startIndex > 0;
  const hasTools = Array.isArray(tools) && tools.length > 0;

  let toolSection = '';
  if (hasTools && !isIncremental) {
    // 精简工具定义，保留名称、简介、参数名与必填项以降低体积
    const toolDefs = tools.map((t) => {
      const fn = t.function || t;
      const props = fn.parameters?.properties ? Object.keys(fn.parameters.properties) : [];
      const req = Array.isArray(fn.parameters?.required) ? fn.parameters.required : [];
      return {
        name: fn.name,
        ...(fn.description ? { desc: String(fn.description).slice(0, 140) } : {}),
        ...(props.length > 0 ? { args: props } : {}),
        ...(req.length > 0 ? { required: req } : {}),
      };
    });

    const choiceHint =
      toolChoice === 'none'
        ? 'Answer directly without invoking any client function.'
        : toolChoice === 'required'
        ? 'Select and invoke one of the client functions below to proceed.'
        : typeof toolChoice === 'object' && toolChoice?.function?.name
        ? `Invoke the "${toolChoice.function.name}" client function below.`
        : 'When the task involves local files, codebases, or commands, call these client functions instead of saying you lack local access.';

    toolSection = [
      '[Client Functions]',
      'The user is using a local client that executes the following functions in their local workspace and returns the output to you.',
      choiceHint,
      `Call format (output the tag directly outside code blocks, then stop and wait for Tool output): ${TOOL_CALL_OPEN}{"name":"<name>","arguments":{...}}${TOOL_CALL_CLOSE}`,
      `Functions: ${JSON.stringify(toolDefs)}`,
    ].join('\n');
  } else if (hasTools && isIncremental) {
    toolSection = `[Client Functions Active: use ${TOOL_CALL_OPEN}{"name":"<name>","arguments":{...}}${TOOL_CALL_CLOSE} directly for local workspace actions instead of saying you lack local access.]`;
  }

  const allMsgs = Array.isArray(messages) ? messages : [];
  const slice = allMsgs.slice(startIndex);

  if (slice.length > 0) {
    if (allMsgs.length === 1 && slice[0].role === 'user' && (!tools || tools.length === 0)) {
      const raw = typeof slice[0].content === 'string'
        ? slice[0].content
        : JSON.stringify(slice[0].content);
      return splitPromptIntoChunks(raw, '');
    }

    for (let idx = 0; idx < slice.length; idx++) {
      const m = slice[idx];
      const text =
        typeof m.content === 'string'
          ? m.content
          : Array.isArray(m.content)
          ? m.content.map((p) => (p.type === 'text' ? p.text : '')).join('')
          : m.content == null
          ? ''
          : JSON.stringify(m.content);

      if (m.role === 'assistant' && Array.isArray(m.tool_calls) && m.tool_calls.length > 0) {
        const callsText = m.tool_calls
          .map(
            (tc) =>
              `${TOOL_CALL_OPEN}${JSON.stringify({
                name: tc.function?.name,
                arguments:
                  typeof tc.function?.arguments === 'string'
                    ? (() => {
                        try {
                          return JSON.parse(tc.function.arguments);
                        } catch {
                          return tc.function.arguments;
                        }
                      })()
                    : tc.function?.arguments ?? {},
              })}${TOOL_CALL_CLOSE}`
          )
          .join('\n');
        parts.push(`Assistant: ${text ? `${text}\n` : ''}${callsText}`);
      } else if (m.role === 'tool') {
        parts.push(`Tool output (${m.name || m.tool_call_id || 'tool'}):\n${text}`);
      } else if (m.role === 'system' || m.role === 'developer') {
        parts.push(`Context: ${text}`);
      } else if (m.role === 'assistant') {
        parts.push(`Assistant: ${text}`);
      } else {
        parts.push(`User: ${text}`);
      }
    }
  }

  return splitPromptIntoChunks(parts.join('\n\n'), toolSection);
}

function splitPromptIntoChunks(bodyText, toolSection) {
  const full = toolSection ? `${bodyText}\n\n${toolSection}` : bodyText;
  if (Buffer.byteLength(full, 'utf8') <= MAX_QUICK_PROMPT_BYTES) {
    return [full];
  }

  // 为分片头部与末尾 toolSection 预留空间，避免单片超 42KB
  const headerReserve = 160;
  const toolBytes = toolSection ? Buffer.byteLength(toolSection, 'utf8') + 16 : 0;
  const bodyMax = Math.max(8 * 1024, MAX_QUICK_PROMPT_BYTES - headerReserve - toolBytes);
  let rawChunks = splitUtf8ByMaxBytes(bodyText, bodyMax);
  if (rawChunks.length > MAX_PROMPT_CHUNKS) {
    // 超过最大分片数时保留开头与末尾分片，避免无限耗时
    rawChunks = [
      rawChunks[0],
      `...[omitted ${rawChunks.length - MAX_PROMPT_CHUNKS} middle part(s) exceeding max ${MAX_PROMPT_CHUNKS} chunks]...`,
      ...rawChunks.slice(-(MAX_PROMPT_CHUNKS - 2)),
    ];
  }
  const total = rawChunks.length;
  return rawChunks.map((chunk, i) => {
    const isLast = i === total - 1;
    if (!isLast) {
      return `[Message Part ${i + 1}/${total} - Read and store this part in context, then reply ONLY "ACK" without answering yet.]\n\n${chunk}`;
    }
    const finalBody = `[Message Part ${total}/${total} - Final part. Now respond to the full request across all parts.]\n\n${chunk}`;
    return toolSection ? `${finalBody}\n\n${toolSection}` : finalBody;
  });
}

function extractToolCallsFromText(text) {
  const toolCalls = [];
  const regex = new RegExp(`${TOOL_CALL_OPEN}\\s*([\\s\\S]*?)\\s*${TOOL_CALL_CLOSE}`, 'g');
  let cleanText = text;
  let match;
  let idx = 0;

  while ((match = regex.exec(text)) !== null) {
    const rawJson = match[1].trim();
    try {
      const parsed = JSON.parse(rawJson);
      if (parsed && typeof parsed.name === 'string') {
        toolCalls.push({
          index: idx++,
          id: `call_${crypto.randomBytes(12).toString('hex')}`,
          type: 'function',
          function: {
            name: parsed.name,
            arguments:
              typeof parsed.arguments === 'string'
                ? parsed.arguments
                : JSON.stringify(parsed.arguments ?? {}),
          },
        });
      }
    } catch {
      // 忽略解析失败的片段
    }
  }

  if (toolCalls.length > 0) {
    cleanText = text.replace(regex, '').trim();
  }
  return { toolCalls, cleanText };
}

/**
 * 实时流式标签过滤器：
 * - 普通文本不等待整轮结束，除末尾可能匹配 <qw_tool_call> 前缀的字符外全部实时推送
 * - 一旦遇到 <qw_tool_call>...</qw_tool_call>，静默缓冲并解析为 tool_calls 回调
 */
function createStreamingToolFilter({ onText, onToolCall }) {
  let buf = '';
  let inTag = false;
  let toolIndex = 0;

  function longestPrefixOverlap(str, target) {
    const maxLen = Math.min(str.length, target.length - 1);
    for (let len = maxLen; len > 0; len--) {
      if (str.endsWith(target.slice(0, len))) return len;
    }
    return 0;
  }

  function processBuffer() {
    while (buf.length > 0) {
      if (!inTag) {
        const openIdx = buf.indexOf(TOOL_CALL_OPEN);
        if (openIdx !== -1) {
          if (openIdx > 0) onText(buf.slice(0, openIdx));
          buf = buf.slice(openIdx + TOOL_CALL_OPEN.length);
          inTag = true;
          continue;
        }
        const overlap = longestPrefixOverlap(buf, TOOL_CALL_OPEN);
        const safeLen = buf.length - overlap;
        if (safeLen > 0) {
          onText(buf.slice(0, safeLen));
          buf = buf.slice(safeLen);
        }
        break;
      } else {
        const closeIdx = buf.indexOf(TOOL_CALL_CLOSE);
        if (closeIdx === -1) break;
        const rawJson = buf.slice(0, closeIdx).trim();
        buf = buf.slice(closeIdx + TOOL_CALL_CLOSE.length);
        inTag = false;
        try {
          const parsed = JSON.parse(rawJson);
          if (parsed && typeof parsed.name === 'string') {
            onToolCall({
              index: toolIndex++,
              id: `call_${crypto.randomBytes(12).toString('hex')}`,
              type: 'function',
              function: {
                name: parsed.name,
                arguments:
                  typeof parsed.arguments === 'string'
                    ? parsed.arguments
                    : JSON.stringify(parsed.arguments ?? {}),
              },
            });
          }
        } catch {
          // 忽略格式错误的块
        }
      }
    }
  }

  return {
    push(delta) {
      buf += delta;
      processBuffer();
    },
    flush() {
      if (!inTag && buf.length > 0) {
        onText(buf);
      } else if (inTag && buf.length > 0) {
        onText(`${TOOL_CALL_OPEN}${buf}`);
      }
      buf = '';
      inTag = false;
    },
    getToolCount: () => toolIndex,
  };
}

function parseQuickModelAndEffort(reqModel, body, defaults = {}) {
  const raw = String(reqModel || '').trim().toLowerCase();
  const validModes = new Set(['fast', 'balanced', 'smart', 'advanced']);
  const validEfforts = new Set(['off', 'low', 'medium', 'high', 'max']);

  let agentMode = defaults.agentMode || 'smart';
  let thinkingEffort = defaults.thinkingEffort || 'off';

  // 只从 model 解析模型档位（支持 quick-fast / quick-balanced / quick-smart 或 fast / balanced / smart）
  const normalized = raw.startsWith('quick-') ? raw.slice(6) : raw;
  if (validModes.has(normalized)) {
    agentMode = normalized;
  }

  // 统一通过 OpenAI 标准 reasoning_effort（兼容 thinking_effort）映射 thinking_effort
  const reqEffort = body?.reasoning_effort ?? body?.thinking_effort;
  if (typeof reqEffort === 'string') {
    const e = reqEffort.trim().toLowerCase();
    if (e === 'none' || e === 'off') thinkingEffort = 'off';
    else if (validEfforts.has(e)) thinkingEffort = e;
  }

  return { agentMode, thinkingEffort };
}

// 挂起等待客户端回传 tool_result 的 WS 会话池: openAiToolCallId -> sessionState
const pendingToolSessions = new Map();

function hashMessage(m) {
  const norm = {
    role: m?.role || '',
    content: m?.content ?? null,
    name: m?.name ?? null,
    tool_call_id: m?.tool_call_id ?? null,
    tool_calls: m?.tool_calls ?? null,
  };
  return crypto.createHash('sha256').update(JSON.stringify(norm)).digest('hex').slice(0, 16);
}

function hashesMatchPrefix(prefix, full) {
  if (prefix.length > full.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (prefix[i] !== full[i]) return false;
  }
  return true;
}

/**
 * 多 Session 管理器（支持 Fork 分支检测）：
 * - 通过历史消息哈希链精确匹配已有会话，避免 Fork 分支误命中原 Session
 * - 当客户端基于同一历史节点 Fork 出不同分支时，自动派生新 threadId 隔离上下文
 * - 同一会话内顺序排队，不同会话/分支之间完全并发
 */
const MAX_ACTIVE_WS = 3;
const WS_IDLE_CLOSE_MS = 120 * 1000;

class SessionManager {
  #persistDirty = false;
  #persistWriting = false;
  #wsWaiters = [];
  #slotChain = Promise.resolve();

  constructor(ttlMs = 30 * 60 * 1000, persistFile = '') {
    this.ttlMs = ttlMs;
    this.persistFile = persistFile;
    this.sessions = new Map(); // sessionKey -> SessionRecord
  }

  /**
   * 启动时从磁盘 JSON 恢复未过期的 session 信息
   */
  loadFromDisk() {
    if (!this.persistFile || !fs.existsSync(this.persistFile)) return 0;
    try {
      const raw = fs.readFileSync(this.persistFile, 'utf8');
      if (!raw.trim()) return 0;
      const parsed = JSON.parse(raw);
      const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.sessions) ? parsed.sessions : [];
      const now = Date.now();
      let restored = 0;
      let droppedExpired = false;
      for (const item of list) {
        if (!item || typeof item.sessionKey !== 'string' || typeof item.threadId !== 'string') continue;
        const lastActiveAt = typeof item.lastActiveAt === 'number' ? item.lastActiveAt : now;
        if (now - lastActiveAt > this.ttlMs) {
          droppedExpired = true;
          continue;
        }
        const rec = {
          sessionKey: item.sessionKey,
          // 进程重启后原 WS 通道已失效，刷新 WS conversationId 通道以避免 Tenant service stream error，同时保留 threadId 延续上下文
          workingSessionId: crypto.randomUUID(),
          threadId: item.threadId,
          committedHashes: Array.isArray(item.committedHashes) ? item.committedHashes.slice() : [],
          inFlight: 0,
          queue: Promise.resolve(),
          activeWsSession: null,
          createdAt: typeof item.createdAt === 'number' ? item.createdAt : lastActiveAt,
          lastActiveAt,
          ttlTimer: null,
        };
        this.sessions.set(rec.sessionKey, rec);
        this.touch(rec);
        restored++;
      }
      if (droppedExpired) this.schedulePersist();
      return restored;
    } catch (err) {
      logInfo('SESSION', `Failed to load sessions from ${this.persistFile}: ${err.message}`);
      return 0;
    }
  }

  /**
   * 异步写入临时文件并 rename(move) 到目标 JSON 文件，自动合并高频更新
   */
  schedulePersist() {
    if (!this.persistFile) return;
    this.#persistDirty = true;
    if (this.#persistWriting) return;
    queueMicrotask(() => {
      void this.#flushPersistLoop();
    });
  }

  async #flushPersistLoop() {
    if (this.#persistWriting || !this.persistFile) return;
    this.#persistWriting = true;
    try {
      while (this.#persistDirty) {
        this.#persistDirty = false;
        const snapshot = {
          version: 1,
          updatedAt: new Date().toISOString(),
          sessions: [...this.sessions.values()].map((r) => ({
            sessionKey: r.sessionKey,
            workingSessionId: r.workingSessionId,
            threadId: r.threadId,
            committedHashes: r.committedHashes,
            createdAt: r.createdAt,
            lastActiveAt: r.lastActiveAt,
          })),
        };
        const dir = path.dirname(this.persistFile);
        await fs.promises.mkdir(dir, { recursive: true });
        const tmpPath = `${this.persistFile}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
        try {
          await fs.promises.writeFile(tmpPath, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8');
          await fs.promises.rename(tmpPath, this.persistFile);
        } catch (err) {
          try {
            await fs.promises.unlink(tmpPath);
          } catch { /* ignore */ }
          logInfo('SESSION', `Failed to persist sessions to ${this.persistFile}: ${err.message}`);
        }
      }
    } finally {
      this.#persistWriting = false;
    }
  }

  /**
   * 为当前请求解析或创建匹配的 SessionRecord，并计算增量起始下标 startIndex
   */
  resolveSession(req, body) {
    const msgs = Array.isArray(body?.messages) ? body.messages : [];
    const msgHashes = msgs.map(hashMessage);

    const headerId = req.headers['x-session-id'] || req.headers['x-conversation-id'];
    const bodyId = body?.session_id || body?.conversation_id || body?.user;
    const explicit = typeof (headerId || bodyId) === 'string' ? (headerId || bodyId).trim() : '';

    // 1. 显式指定了 sessionId：检查历史前缀是否一致；若发生回滚/Fork 则重置为新 threadId
    if (explicit) {
      const key = `explicit:${explicit}`;
      let rec = this.sessions.get(key);
      if (!rec) {
        rec = this.#createRecord(key);
      } else if (
        rec.committedHashes.length > 0 &&
        !hashesMatchPrefix(rec.committedHashes, msgHashes)
      ) {
        // 客户端在该 explicit ID 下回溯/Fork 了历史，重置云端 threadId 防止串话
        if (rec.activeWsSession) {
          closeWsSession(rec.activeWsSession);
          rec.activeWsSession = null;
        }
        rec.workingSessionId = crypto.randomUUID();
        rec.threadId = crypto.randomUUID();
        rec.committedHashes = [];
        this.schedulePersist();
      }
      const startIndex =
        rec.committedHashes.length > 0 && msgHashes.length > rec.committedHashes.length
          ? rec.committedHashes.length
          : 0;
      this.touch(rec);
      return { rec, startIndex, isFork: false };
    }

    // 2. 自动识别模式（未显式传 sessionId）：在已有会话中寻找 committedHashes 与当前前缀最长匹配的会话
    let bestRec = null;
    let bestLen = -1;

    for (const rec of this.sessions.values()) {
      if (!rec.sessionKey.startsWith('auto:')) continue;
      const cLen = rec.committedHashes.length;
      if (cLen === 0 || cLen >= msgHashes.length) continue;

      if (hashesMatchPrefix(rec.committedHashes, msgHashes)) {
        // 要求正在处理的分支与当前请求不是同一节点的并发分叉（若正在 inFlight 且末尾不同，不可复用）
        if (rec.inFlight > 0) continue;
        if (cLen > bestLen) {
          bestLen = cLen;
          bestRec = rec;
        }
      }
    }

    if (bestRec) {
      this.touch(bestRec);
      return { rec: bestRec, startIndex: bestRec.committedHashes.length, isFork: false };
    }

    // 未命中精确前缀（全新会话，或从已有历史节点 Fork 出的新分支） -> 创建独立 Session
    const isFork = msgs.length > 1;
    const newKey = `auto:${crypto.randomUUID().slice(0, 16)}`;
    const rec = this.#createRecord(newKey);
    this.touch(rec);
    return { rec, startIndex: 0, isFork };
  }

  #createRecord(sessionKey) {
    const rec = {
      sessionKey,
      workingSessionId: crypto.randomUUID(),
      threadId: crypto.randomUUID(),
      committedHashes: [],
      inFlight: 0,
      queue: Promise.resolve(),
      activeWsSession: null,
      createdAt: Date.now(),
      lastActiveAt: Date.now(),
      ttlTimer: null,
    };
    this.sessions.set(sessionKey, rec);
    this.schedulePersist();
    return rec;
  }

  commitHashes(rec, msgHashes) {
    rec.committedHashes = msgHashes.slice();
    this.touch(rec);
    this.schedulePersist();
  }

  touch(rec) {
    rec.lastActiveAt = Date.now();
    if (rec.ttlTimer) clearTimeout(rec.ttlTimer);
    rec.ttlTimer = setTimeout(() => {
      if (rec.inFlight === 0) {
        if (rec.activeWsSession) {
          closeWsSession(rec.activeWsSession);
          rec.activeWsSession = null;
        }
        this.sessions.delete(rec.sessionKey);
        this.schedulePersist();
      }
    }, this.ttlMs);
    rec.ttlTimer.unref?.();
  }

  /**
   * 统计当前活跃（OPEN / CONNECTING）的 WebSocket 连接数
   */
  countActiveWs() {
    const seen = new Set();
    let count = 0;
    for (const r of this.sessions.values()) {
      const ws = r.activeWsSession?.ws;
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        seen.add(ws);
        count++;
      }
    }
    for (const s of pendingToolSessions.values()) {
      const ws = s?.ws;
      if (ws && !seen.has(ws) && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        seen.add(ws);
        count++;
      }
    }
    return count;
  }

  /**
   * 驱逐最久未使用的空闲 WS 连接（inFlight === 0）并等待其关闭
   */
  async evictOldestIdleWs(excludeRec = null) {
    const candidates = [...this.sessions.values()]
      .filter(
        (r) =>
          r !== excludeRec &&
          r.inFlight === 0 &&
          r.activeWsSession?.ws &&
          (r.activeWsSession.ws.readyState === WebSocket.OPEN ||
            r.activeWsSession.ws.readyState === WebSocket.CONNECTING)
      )
      .sort((a, b) => a.lastActiveAt - b.lastActiveAt);

    if (candidates.length === 0) return false;
    const victim = candidates[0];
    const wsSession = victim.activeWsSession;
    victim.activeWsSession = null;
    logInfo('WS', `Evicting idle extension WS session=${victim.sessionKey} to free connection slot`);
    await closeWsSession(wsSession, true);
    await new Promise((r) => setTimeout(r, 300));
    return true;
  }

  notifyWsWaiters() {
    while (this.#wsWaiters.length > 0) {
      const hasFreeSlot = this.countActiveWs() < MAX_ACTIVE_WS;
      const hasIdleToEvict = [...this.sessions.values()].some(
        (r) =>
          r.inFlight === 0 &&
          r.activeWsSession?.ws &&
          (r.activeWsSession.ws.readyState === WebSocket.OPEN ||
            r.activeWsSession.ws.readyState === WebSocket.CONNECTING)
      );
      if (!hasFreeSlot && !hasIdleToEvict) break;
      const wake = this.#wsWaiters.shift();
      wake?.();
    }
  }

  /**
   * 申请一个 WS 连接槽位（全局最多 MAX_ACTIVE_WS=3 个活跃连接）：
   * - 若已达上限，优先驱逐最久未使用的空闲 WS 连接
   * - 若全部连接都在请求处理中，排队等待任一请求释放槽位
   */
  acquireWsSlot(currentRec = null) {
    const run = this.#slotChain.then(async () => {
      while (this.countActiveWs() >= MAX_ACTIVE_WS) {
        const evicted = await this.evictOldestIdleWs(currentRec);
        if (evicted) continue;
        logInfo('WS', `Active WS connections reached limit (${MAX_ACTIVE_WS}), waiting for a free slot...`);
        await new Promise((resolve) => {
          this.#wsWaiters.push(resolve);
        });
      }
    });
    this.#slotChain = run.catch(() => {});
    return run;
  }

  /**
   * 同一 sessionKey 内的请求串行排队；不同 sessionKey 之间完全并行
   */
  enqueue(rec, taskFn) {
    rec.inFlight += 1;
    if (rec.activeWsSession?.idleCloseTimer) {
      clearTimeout(rec.activeWsSession.idleCloseTimer);
      rec.activeWsSession.idleCloseTimer = null;
    }
    const run = rec.queue.then(() => taskFn(rec), () => taskFn(rec));
    rec.queue = run.catch(() => {});
    return run.finally(() => {
      rec.inFlight = Math.max(0, rec.inFlight - 1);
      if (rec.inFlight === 0 && rec.activeWsSession?.isExtension) {
        if (rec.activeWsSession.idleCloseTimer) clearTimeout(rec.activeWsSession.idleCloseTimer);
        rec.activeWsSession.idleCloseTimer = setTimeout(() => {
          if (rec.inFlight === 0 && rec.activeWsSession) {
            const s = rec.activeWsSession;
            rec.activeWsSession = null;
            void closeWsSession(s, false);
            this.notifyWsWaiters();
          }
        }, WS_IDLE_CLOSE_MS);
        rec.activeWsSession.idleCloseTimer.unref?.();
      }
      this.touch(rec);
      this.notifyWsWaiters();
    });
  }

  summary() {
    return [...this.sessions.values()].map((r) => ({
      sessionKey: r.sessionKey,
      workingSessionId: r.workingSessionId,
      threadId: r.threadId,
      committedCount: r.committedHashes.length,
      inFlight: r.inFlight,
      lastActiveAt: new Date(r.lastActiveAt).toISOString(),
    }));
  }
}

function mapQuickToolToClientTool(quickToolName, quickArgs, clientTools) {
  const names = (clientTools || []).map((t) => (t.function || t).name).filter(Boolean);
  const lowerMap = new Map(names.map((n) => [n.toLowerCase(), n]));
  const qLower = String(quickToolName || '').toLowerCase();

  // 1. 同名直接匹配
  let mappedName = lowerMap.get(qLower);
  // 2. 常见工具名别名映射 (Quick -> OpenAI/pi)
  if (!mappedName) {
    const aliasGroups = [
      [['file_read', 'read_file', 'read_text_file', 'view_file'], ['read', 'read_file', 'file_read']],
      [['file_write', 'write_file', 'write_to_file'], ['write', 'write_file', 'file_write']],
      [['file_edit', 'edit_file', 'str_replace', 'replace_file_content'], ['edit', 'edit_file', 'file_edit']],
      [['bash', 'shell', 'execute_command', 'run_command', 'run_terminal_command'], ['bash', 'shell', 'exec', 'run_command']],
      [['list_dir', 'list_directory', 'glob', 'find_files'], ['glob', 'find', 'ls', 'list_dir']],
      [['grep', 'search_files', 'ripgrep'], ['grep', 'search']],
    ];
    for (const [quickAliases, clientAliases] of aliasGroups) {
      if (quickAliases.some((a) => qLower.includes(a))) {
        for (const ca of clientAliases) {
          if (lowerMap.has(ca)) {
            mappedName = lowerMap.get(ca);
            break;
          }
        }
        if (mappedName) break;
      }
    }
  }

  const finalName = mappedName || quickToolName;
  let argsObj = quickArgs && typeof quickArgs === 'object' ? { ...quickArgs } : {};
  // 常见参数名归一化：file_path / filepath -> path（若客户端 schema 使用 path）
  const matchedTool = (clientTools || []).find((t) => (t.function || t).name === finalName);
  const props = matchedTool?.function?.parameters?.properties || matchedTool?.parameters?.properties || {};
  if (props.path && !argsObj.path) {
    if (argsObj.file_path) argsObj.path = argsObj.file_path;
    else if (argsObj.filepath) argsObj.path = argsObj.filepath;
    else if (argsObj.target_file) argsObj.path = argsObj.target_file;
  }

  return {
    id: `call_${crypto.randomBytes(12).toString('hex')}`,
    type: 'function',
    function: {
      name: finalName,
      arguments: JSON.stringify(argsObj),
    },
  };
}

function encodeOutboundByMode(sessionState, obj) {
  if (sessionState.isExtension) return encodeExtensionFrame(obj);
  if (sessionState.isAidp) return encodeAidpInputEvent(obj);
  return encodeGatewayFrame(obj);
}

function decodeInboundByMode(sessionState, bytes) {
  if (sessionState.isExtension) return decodeExtensionFrame(bytes);
  if (sessionState.isAidp) return decodeAidpOutputEvent(bytes);
  return decodeGatewayFrame(bytes);
}

function closeWsSession(sessionState, waitClose = false) {
  if (!sessionState) return Promise.resolve();
  if (sessionState.keepaliveTimer) {
    clearInterval(sessionState.keepaliveTimer);
    sessionState.keepaliveTimer = null;
  }
  if (sessionState.ttlTimer) {
    clearTimeout(sessionState.ttlTimer);
    sessionState.ttlTimer = null;
  }
  if (sessionState.idleCloseTimer) {
    clearTimeout(sessionState.idleCloseTimer);
    sessionState.idleCloseTimer = null;
  }
  const ws = sessionState.ws;
  if (!ws || ws.readyState === WebSocket.CLOSED) return Promise.resolve();

  const waitPromise = waitClose
    ? new Promise((resolve) => {
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          ws.removeEventListener('close', finish);
          resolve();
        };
        const timer = setTimeout(finish, 1500);
        timer.unref?.();
        ws.addEventListener('close', finish, { once: true });
      })
    : Promise.resolve();

  try {
    ws.close(1000, 'done');
  } catch {
    return Promise.resolve();
  }
  return waitPromise;
}

function attachWsSessionTurn(sessionState, { reqId = '-', clientTools, signal, onThought, onDelta }) {
  const { ws, isAidp, isExtension, threadId } = sessionState;
  const sendPayload = (obj) => {
    logDebug('WS', `[${reqId}] send type=${obj.type}`);
    ws.send(encodeOutboundByMode(sessionState, obj));
  };

  return new Promise((resolve, reject) => {
    let settled = false;
    let fullText = '';
    let fullThought = '';
    let usage = null;
    let resolvedModel = null;

    const cleanupListeners = () => {
      ws.removeEventListener('message', onMessage);
      ws.removeEventListener('error', onError);
      ws.removeEventListener('close', onClose);
      signal?.removeEventListener('abort', onAbort);
    };

    const closeWs = () => {
      if (sessionState.keepaliveTimer) {
        clearInterval(sessionState.keepaliveTimer);
        sessionState.keepaliveTimer = null;
      }
      if (sessionState.ttlTimer) {
        clearTimeout(sessionState.ttlTimer);
        sessionState.ttlTimer = null;
      }
      try {
        ws.close(1000, 'done');
      } catch {
        // ignore
      }
    };

    const onAbort = () => {
      if (!settled) {
        settled = true;
        try {
          sendPayload({ type: isAidp ? 'cancel_run' : 'cancel', thread_id: threadId });
        } catch { /* ignore */ }
        cleanupListeners();
        closeWs();
        resolve({ text: fullText, thought: fullThought, usage, model: resolvedModel, toolCalls: [], finishReason: 'stop' });
      }
    };

    if (signal) {
      if (signal.aborted) return onAbort();
      signal.addEventListener('abort', onAbort, { once: true });
    }

    const onMessage = (event) => {
      if (settled) return;
      try {
        let msg = null;
        if (typeof event.data === 'string') msg = JSON.parse(event.data);
        else {
          const bytes = new Uint8Array(event.data);
          msg = decodeInboundByMode(sessionState, bytes);
        }
        if (!msg || typeof msg !== 'object') return;

        if ((isAidp || isExtension) && msg.type === 'session_established') {
          logDebug('WS', `[${reqId}] session_established workingSessionId=${msg.workingSessionId}`);
          sessionState.onEstablished?.();
          return;
        }
        if (msg.type === 'turn_usage' && msg.payload) {
          usage = msg.payload;
          resolvedModel = msg.payload.served_model_id || msg.payload.resolved_model_id || null;
          logInfo('USAGE', `[${reqId}]`, usage);
          return;
        }
        if (msg.type === 'tool_call' && msg.payload) {
          const quickToolCallId = msg.payload.tool_call_id;
          const quickToolName = msg.payload.tool_name;
          const quickArgs = msg.payload.arguments;
          logInfo('WS', `[${reqId}] tool_call received: name=${quickToolName} id=${quickToolCallId}`);

          if (Array.isArray(clientTools) && clientTools.length > 0) {
            const mapped = mapQuickToolToClientTool(quickToolName, quickArgs, clientTools);
            settled = true;
            cleanupListeners();

            // 保活挂起 WS 等待下一轮客户端回传 tool_result
            sessionState.quickToolCallId = quickToolCallId;
            if (!sessionState.keepaliveTimer) {
              sessionState.keepaliveTimer = setInterval(() => {
                try {
                  sendPayload({ type: 'ping', payload: { timestamp: Date.now() } });
                } catch { /* ignore */ }
              }, 25000);
            }
            if (sessionState.ttlTimer) clearTimeout(sessionState.ttlTimer);
            sessionState.ttlTimer = setTimeout(() => {
              pendingToolSessions.delete(mapped.id);
              closeWs();
            }, 5 * 60 * 1000);

            pendingToolSessions.set(mapped.id, sessionState);
            resolve({
              text: fullText,
              thought: fullThought,
              usage,
              model: resolvedModel,
              toolCalls: [mapped],
              finishReason: 'tool_calls',
            });
            return;
          }

          // 未传 tools 时拒绝对话内设备工具，避免云端无限等待
          sendPayload({
            type: 'tool_result',
            payload: {
              tool_call_id: quickToolCallId,
              result: null,
              error: 'Client has no local tools enabled.',
            },
          });
          return;
        }
        if (msg.type === 'thinking_delta' || msg.type === 'thought_delta' || msg.type === 'reasoning_delta') {
          const delta = msg.payload?.delta ?? msg.text ?? msg.delta ?? '';
          if (typeof delta === 'string' && delta) {
            fullThought += delta;
            onThought?.(delta);
          }
        } else if (msg.type === 'text_delta' || msg.type === 'content_delta' || msg.type === 'message_chunk') {
          const delta = msg.payload?.delta ?? msg.text ?? msg.delta ?? msg.content ?? '';
          if (typeof delta === 'string' && delta) {
            fullText += delta;
            onDelta?.(delta);
          }
        } else if (msg.type === 'message_complete' || msg.type === 'turn_complete' || msg.type === 'done') {
          const finalTxt = msg.payload?.text ?? msg.text ?? '';
          if (typeof finalTxt === 'string' && finalTxt && !fullText) {
            fullText = finalTxt;
            onDelta?.(finalTxt);
          }
          logInfo('WS', `[${reqId}] message_complete textLen=${fullText.length} thoughtLen=${fullThought.length}`);
          settled = true;
          cleanupListeners();
          if (sessionState.isExtension) {
            // 浏览器扩展在同一 conversationId 下保持单条长连接，避免短时间内重连触发 limitExceededException
            if (!sessionState.keepaliveTimer) {
              sessionState.keepaliveTimer = setInterval(() => {
                try {
                  sendPayload({ type: 'ping', payload: { timestamp: Date.now() } });
                } catch { /* ignore */ }
              }, 25000);
              sessionState.keepaliveTimer.unref?.();
            }
          } else {
            closeWs();
          }
          resolve({ text: fullText, thought: fullThought, usage, model: resolvedModel, toolCalls: [], finishReason: 'stop' });
        } else if (msg.type === 'error') {
          logInfo('WS', `[${reqId}] upstream error event`, msg);
          settled = true;
          cleanupListeners();
          closeWs();
          reject(new Error(msg.payload?.message || msg.message || msg.error || 'Quick WS error'));
        }
      } catch (err) {
        logInfo('WS', `[${reqId}] message decode/handle error: ${err?.stack || err}`);
        settled = true;
        cleanupListeners();
        closeWs();
        reject(err);
      }
    };

    const onError = (ev) => {
      const detail = ev?.message || ev?.error?.message || ev?.type || 'unknown error';
      logInfo('WS', `[${reqId}] WebSocket error (${sessionState.resolvedHost}): ${detail}`);
      if (!settled) {
        settled = true;
        cleanupListeners();
        closeWs();
        reject(new Error(`Quick WebSocket connection failed (${sessionState.resolvedHost}): ${detail}`));
      }
    };

    const onClose = (ev) => {
      logDebug('WS', `[${reqId}] WebSocket closed code=${ev?.code} reason=${ev?.reason || ''}`);
      if (!settled) {
        settled = true;
        cleanupListeners();
        if (ev?.code && ev.code !== 1000 && !fullText && !fullThought) {
          reject(new Error(`Quick WebSocket closed abnormally (code=${ev.code}${ev?.reason ? `, reason=${ev.reason}` : ''})`));
        } else {
          resolve({ text: fullText, thought: fullThought, usage, model: resolvedModel, toolCalls: [], finishReason: 'stop' });
        }
      }
    };

    ws.addEventListener('message', onMessage);
    ws.addEventListener('error', onError);
    ws.addEventListener('close', onClose);
  });
}

function callQuickWsTurn({
  reqId = '-',
  jwt,
  cookie,
  csrfToken,
  serviceEndpoint,
  accountId,
  accountAlias,
  wsHost,
  tenantUrl,
  provider,
  outpostId,
  agentId,
  runtimeArn,
  workingSessionId: givenWorkingSessionId,
  threadId: givenThreadId,
  agentMode = 'smart',
  thinkingEffort = 'off',
  clientTools,
  promptText,
  signal,
  onThought,
  onDelta,
  onSessionCreated,
}) {
  const isExtension = provider === 'extension';
  const isAidp = provider === 'social' || provider === 'enterprise';
  const resolvedHost = wsHost || (serviceEndpoint ? new URL(serviceEndpoint).host : '') || (tenantUrl ? new URL(tenantUrl).host : '');
  if (!resolvedHost) {
    throw new Error('Missing Quick host in credentials JSON (wsHost / serviceEndpoint).');
  }
  if (isExtension && (!cookie || !csrfToken || !accountId)) {
    throw new Error('Missing browser extension credentials in credentials JSON (cookie, csrfToken, accountId).');
  }
  if (!isExtension && !jwt) {
    throw new Error('Missing Quick JWT in credentials JSON (jwt).');
  }

  const traceId = crypto.randomUUID();
  const workingSessionId = givenWorkingSessionId || crypto.randomUUID();
  const threadId = givenThreadId || crypto.randomUUID();

  let wsUrl;
  let headers;
  let protocols;
  if (isExtension) {
    const wsPath = getExtensionPathPrefix(
      'wsproxy/service/SpaceNeedleConversationService/operation/ChatBidirectionalStream',
      accountAlias
    );
    const extOutpostId = outpostId && String(outpostId).startsWith('bext-')
      ? outpostId
      : `bext-${outpostId || crypto.randomUUID()}`;
    const params = new URLSearchParams({
      'wsproxy-protocol': 'rpc-v2-cbor',
      awsAccountId: accountId,
      surfaceType: 'BROWSER_EXTENSION_CHROME',
      agentServiceType: 'UNIFIED_QUICK',
      mbtc: decodeURIComponent(csrfToken),
      outpostId: extOutpostId,
      conversationId: workingSessionId,
    });
    if (runtimeArn) params.set('agentRuntimeArnOverride', runtimeArn);
    wsUrl = `wss://${resolvedHost}${wsPath}?${params.toString()}`;
    const origin = serviceEndpoint || `https://${resolvedHost}`;
    headers = {
      Cookie: cookie,
      Origin: origin,
      'x-amzn-csrf-token': csrfToken,
      'x-amzn-qs-internal-trace-id': traceId,
    };
    protocols = ['subprotocol-json', encodeURIComponent(JSON.stringify({ csrfToken }))];
  } else if (isAidp) {
    const surface = process.platform === 'win32' ? 'QUICK_WORK_DESKTOP_WINDOWS' : 'QUICK_WORK_DESKTOP_MAC';
    const params = new URLSearchParams({
      surfaceType: surface,
      token: jwt,
      workingSessionId,
      channel: 'prod',
    });
    if (outpostId) params.set('outpostId', outpostId);
    if (agentId) params.set('agentId', agentId);
    if (runtimeArn) params.set('agentRuntimeArnOverride', runtimeArn);
    wsUrl = `wss://${resolvedHost}/streaming/quickwork-chat-bidirectional-stream?${params.toString()}`;
    headers = { 'x-amzn-qs-internal-trace-id': traceId };
  } else {
    wsUrl = `wss://${resolvedHost}/streaming/quickwork-chat-bidirectional-stream`;
    headers = { Authorization: `Bearer ${jwt}`, 'x-amzn-qs-internal-trace-id': traceId };
  }

  logDebug('WS', `[${reqId}] dialing ${wsUrl.replace(/(token|mbtc)=[^&]+/g, '$1=<redacted>')}`);

  const ws = new WebSocket(wsUrl, protocols ? { headers, protocols } : { headers });
  ws.binaryType = 'arraybuffer';

  let sent = false;
  const sendTurn = () => {
    if (sent) return;
    sent = true;
    logInfo('WS', `[${reqId}] sending turn threadId=${threadId} mode=${agentMode} effort=${thinkingEffort} promptLen=${promptText.length}`);
    const payloadObj =
      isAidp || isExtension
        ? {
            type: 'user_message',
            payload: {
              thread_id: threadId,
              text: promptText,
              message_id: crypto.randomUUID(),
              agent_mode: agentMode,
              ...(thinkingEffort && thinkingEffort !== 'off' ? { thinking_effort: thinkingEffort } : {}),
            },
          }
        : {
            type: 'chat_message',
            conversationId: workingSessionId,
            content: promptText,
            agent_mode: agentMode,
            ...(thinkingEffort && thinkingEffort !== 'off' ? { thinking_effort: thinkingEffort } : {}),
            ...(agentId ? { agentId } : {}),
          };
    ws.send(
      isExtension
        ? encodeExtensionFrame(payloadObj)
        : isAidp
        ? encodeAidpInputEvent(payloadObj)
        : encodeGatewayFrame(payloadObj)
    );
  };

  const sessionState = {
    ws,
    isAidp,
    isExtension,
    threadId,
    resolvedHost,
    keepaliveTimer: null,
    ttlTimer: null,
    onEstablished: () => sendTurn(),
  };
  onSessionCreated?.(sessionState);

  ws.addEventListener('open', () => {
    logDebug('WS', `[${reqId}] WebSocket open`);
    if (!isAidp && !isExtension) sendTurn();
  });

  return attachWsSessionTurn(sessionState, { reqId, clientTools, signal, onThought, onDelta });
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

function parseJwtExpSeconds(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return typeof payload?.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}

function isTokenExpiringSoon(creds, skewSeconds = 60) {
  const nowSec = Date.now() / 1000;
  const expSec = creds.usableUntil ?? parseJwtExpSeconds(creds.jwt);
  if (typeof expSec !== 'number' || !Number.isFinite(expSec)) return false;
  return nowSec >= expSec - skewSeconds;
}

function isAuthError(err) {
  const msg = String(err?.message || err || '').toLowerCase();
  return (
    msg.includes('401') ||
    msg.includes('unauthorized') ||
    msg.includes('expired') ||
    msg.includes('invalid token') ||
    msg.includes('connection failed')
  );
}

async function runServeCommand(flags) {
  if (flags.debug === 'true') DEBUG_ENABLED = true;
  const host = flags.host || process.env.HOST || '127.0.0.1';
  const port = Number(flags.port || process.env.PORT || 8080);
  const proxyApiKey = flags['api-key'] || process.env.OPENAI_API_KEY || '';
  const skewSeconds = Number(flags['refresh-skew'] || process.env.QUICK_REFRESH_SKEW_SECONDS || 60);
  const credsFile = resolveCredsFilePath(flags);
  const fileCreds = loadCredsFromFile(credsFile);

  const initialUsableUntil = fileCreds?.usableUntil ?? null;

  const creds = {
    provider: fileCreds?.provider || 'extension',
    cookie: normalizeCookieInput(fileCreds?.cookie || ''),
    csrfToken: fileCreds?.csrfToken || '',
    serviceEndpoint: fileCreds?.serviceEndpoint || '',
    jwt: fileCreds?.jwt || '',
    wsHost: fileCreds?.wsHost || '',
    tenantUrl: fileCreds?.tenantUrl || '',
    accountId: fileCreds?.accountId || '',
    accountAlias: fileCreds?.accountAlias || '',
    region: fileCreds?.region || 'us-east-1',
    outpostId: resolveOutpostId(flags),
    agentId: fileCreds?.agentId || '',
    runtimeArn: fileCreds?.runtimeArn || '',
    usableUntil: Number.isFinite(Number(initialUsableUntil)) ? Number(initialUsableUntil) : null,
  };

  // 若仅有 Cookie 而无 csrfToken，自动通过 /sn/start 提取 page-config；若完全没有凭证，打印登录 URL 引导交互输入
  if (creds.provider === 'extension' && (!creds.cookie || !creds.csrfToken || !creds.accountId)) {
    if (!creds.cookie) {
      const loginUrl = buildExtensionLoginUrl({
        region: flags.region || creds.region,
        accountAlias: flags.alias || creds.accountAlias,
      });
      if (!process.stdin.isTTY && flags.cookie === undefined) {
        process.stderr.write(
          `Error: No credentials found in ${credsFile}.\n` +
            `Please sign in at: ${loginUrl}\n` +
            `Then run: node aws-quick-openai-api.mjs creds\n`
        );
        process.exit(1);
      }
      creds.cookie = await promptForCookieInteractive(loginUrl);
    }
    const fresh = await fetchExtensionConfigWithCookie({
      cookie: creds.cookie,
      region: flags.region || creds.region,
      accountAlias: flags.alias || creds.accountAlias,
      endpointOverride: flags.endpoint || creds.serviceEndpoint,
    });
    Object.assign(creds, fresh);
    saveCredsToFile(credsFile, creds);
    process.stderr.write(`[quick-openai] Credentials saved to ${credsFile}\n`);
  } else if (creds.provider !== 'extension' && (!creds.jwt || (!creds.wsHost && !creds.tenantUrl))) {
    process.stderr.write(
      'Error: Missing Quick credentials. Run `node aws-quick-openai-api.mjs creds` first.\n'
    );
    process.exit(1);
  } else if (!fileCreds && flags['no-save'] !== 'true') {
    saveCredsToFile(credsFile, creds);
  }

  const sessionsFile = path.resolve(flags['sessions-file'] || process.env.QUICK_SESSIONS_FILE || DEFAULT_SESSIONS_FILE);
  const sessionManager = new SessionManager(30 * 60 * 1000, sessionsFile);
  const restoredSessions = sessionManager.loadFromDisk();
  if (restoredSessions > 0) {
    logInfo('SESSION', `Restored ${restoredSessions} session(s) from ${sessionsFile}`);
  }

  // 并发安全的凭证刷新锁 (Single-Flight)：基于浏览器扩展逻辑用 Cookie 请求 /sn/start 刷新 csrfToken
  let refreshPromise = null;
  async function ensureFreshCredentials(force = false) {
    if (!force && !isTokenExpiringSoon(creds, skewSeconds)) {
      return creds;
    }
    if (refreshPromise) return refreshPromise;

    refreshPromise = (async () => {
      if (!creds.cookie) {
        const loginUrl = buildExtensionLoginUrl({ region: creds.region, accountAlias: creds.accountAlias });
        throw new Error(`Cannot refresh without Cookie. Please sign in again at ${loginUrl} and run \`node aws-quick-openai-api.mjs creds\`.`);
      }
      logInfo('AUTH', `Token ${force ? 'rejected/invalid' : 'expired or expiring soon'}, refreshing csrfToken via /sn/start...`);
      const fresh = await fetchExtensionConfigWithCookie({
        cookie: creds.cookie,
        region: creds.region,
        accountAlias: creds.accountAlias,
        endpointOverride: creds.serviceEndpoint,
      });
      Object.assign(creds, fresh);
      try {
        saveCredsToFile(credsFile, creds);
        logInfo('AUTH', `Updated credentials file: ${credsFile} (usableUntil=${creds.usableUntil})`);
      } catch (err) {
        logInfo('AUTH', `Warning: failed to update ${credsFile}: ${err.message}`);
      }
      return creds;
    })();

    try {
      return await refreshPromise;
    } finally {
      refreshPromise = null;
    }
  }

  async function callWithAutoRefresh(opts) {
    // 若最后一条消息是 tool_result 且对应挂起中的 WS 会话，直接复用该 WS 回传结果
    const lastMsg = Array.isArray(opts.messages) ? opts.messages[opts.messages.length - 1] : null;
    if (lastMsg?.role === 'tool' && lastMsg.tool_call_id && pendingToolSessions.has(lastMsg.tool_call_id)) {
      const sessionState = pendingToolSessions.get(lastMsg.tool_call_id);
      pendingToolSessions.delete(lastMsg.tool_call_id);
      if (sessionState.ttlTimer) {
        clearTimeout(sessionState.ttlTimer);
        sessionState.ttlTimer = null;
      }
      const toolResultContent =
        typeof lastMsg.content === 'string' ? lastMsg.content : JSON.stringify(lastMsg.content ?? '');
      const resultFrame = {
        type: 'tool_result',
        payload: {
          tool_call_id: sessionState.quickToolCallId,
          result: toolResultContent,
          error: null,
        },
      };
      sessionState.ws.send(encodeOutboundByMode(sessionState, resultFrame));
      return attachWsSessionTurn(sessionState, {
        clientTools: opts.clientTools,
        signal: opts.signal,
        onThought: opts.onThought,
        onDelta: opts.onDelta,
      });
    }

    await ensureFreshCredentials(false);
    const rec = opts.sessionRec;
    const chunks = Array.isArray(opts.promptChunks) && opts.promptChunks.length > 0
      ? opts.promptChunks
      : [opts.promptText];

    const sendSinglePrompt = async (chunkText, isFinalChunk) => {
      const turnOpts = isFinalChunk
        ? { ...opts, promptText: chunkText }
        : {
            ...opts,
            promptText: chunkText,
            clientTools: undefined,
            onThought: undefined,
            onDelta: undefined,
          };

      // 浏览器扩展模式：若已有同一会话的活跃 WS 连接，直接复用该长连接发送本轮 user_message
      if (rec?.activeWsSession?.isExtension && rec.activeWsSession.ws?.readyState === WebSocket.OPEN) {
        const active = rec.activeWsSession;
        logInfo('WS', `[${opts.reqId || '-'}] reusing active extension WS threadId=${opts.threadId} promptLen=${chunkText.length}`);
        const payloadObj = {
          type: 'user_message',
          payload: {
            thread_id: opts.threadId,
            text: chunkText,
            message_id: crypto.randomUUID(),
            agent_mode: opts.agentMode || 'smart',
            ...(opts.thinkingEffort && opts.thinkingEffort !== 'off' ? { thinking_effort: opts.thinkingEffort } : {}),
          },
        };
        try {
          active.ws.send(encodeOutboundByMode(active, payloadObj));
          return await attachWsSessionTurn(active, {
            reqId: opts.reqId,
            clientTools: turnOpts.clientTools,
            signal: opts.signal,
            onThought: turnOpts.onThought,
            onDelta: turnOpts.onDelta,
          });
        } catch (err) {
          logInfo('WS', `[${opts.reqId || '-'}] active extension WS failed (${err.message}), reconnecting...`);
          await closeWsSession(active, true);
          rec.activeWsSession = null;
        }
      } else if (rec?.activeWsSession) {
        await closeWsSession(rec.activeWsSession, true);
        rec.activeWsSession = null;
      }

      if (creds.provider === 'extension') {
        await sessionManager.acquireWsSlot(rec);
      }

      const runNewTurn = async () =>
        callQuickWsTurn({
          ...creds,
          ...turnOpts,
          workingSessionId: rec?.workingSessionId || opts.workingSessionId,
          onSessionCreated: (s) => {
            if (rec && s.isExtension) rec.activeWsSession = s;
          },
        });

      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          return await runNewTurn();
        } catch (err) {
          const msg = String(err?.message || '');
          if (isAuthError(err) && creds.cookie && attempt === 0) {
            await ensureFreshCredentials(true);
            continue;
          }
          if (
            creds.provider === 'extension' &&
            (msg.includes('limitExceededException') || msg.includes('Tenant service stream error')) &&
            attempt < 2
          ) {
            if (msg.includes('Too many active connections')) {
              const evicted = await sessionManager.evictOldestIdleWs(rec);
              if (!evicted) await new Promise((r) => setTimeout(r, 800));
              continue;
            }
            if (rec) {
              rec.workingSessionId = crypto.randomUUID();
              rec.activeWsSession = null;
            }
            await new Promise((r) => setTimeout(r, 500));
            continue;
          }
          throw err;
        }
      }
    };

    if (chunks.length > 1) {
      logInfo('WS', `[${opts.reqId || '-'}] splitting oversized prompt into ${chunks.length} messages`);
    }
    for (let i = 0; i < chunks.length - 1; i++) {
      await sendSinglePrompt(chunks[i], false);
    }
    return await sendSinglePrompt(chunks[chunks.length - 1], true);
  }

  const server = http.createServer(async (req, res) => {
    const reqId = crypto.randomBytes(4).toString('hex');
    const startedAt = Date.now();
    const urlPath = (req.url || '/').split('?')[0];
    logInfo('HTTP', `[${reqId}] --> ${req.method} ${req.url} from=${req.socket?.remoteAddress || '-'}`);
    res.on('finish', () => {
      logInfo('HTTP', `[${reqId}] <-- ${res.statusCode} ${urlPath} (${Date.now() - startedAt}ms)`);
    });

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      });
      res.end();
      return;
    }

    if (proxyApiKey && req.url !== '/health') {
      const auth = req.headers.authorization || '';
      if (auth !== `Bearer ${proxyApiKey}`) {
        sendJson(res, 401, { error: { message: 'Invalid API key', type: 'authentication_error' } });
        return;
      }
    }

    if (req.method === 'GET' && urlPath === '/health') {
      sendJson(res, 200, {
        status: 'ok',
        provider: creds.provider,
        usableUntil: creds.usableUntil,
        tokenExpiringSoon: isTokenExpiringSoon(creds, skewSeconds),
        activeSessions: sessionManager.sessions.size,
        sessions: sessionManager.summary(),
      });
      return;
    }

    if (req.method === 'GET' && (urlPath === '/v1/models' || urlPath === '/models')) {
      const nowSec = Math.floor(Date.now() / 1000);
      sendJson(res, 200, {
        object: 'list',
        data: [
          'quick-fast',
          'quick-balanced',
          'quick-smart',
        ].map((id) => ({
          id,
          object: 'model',
          created: nowSec,
          owned_by: 'aws-quick',
        })),
      });
      return;
    }

    if (req.method === 'POST' && (urlPath === '/v1/chat/completions' || urlPath === '/chat/completions')) {
      let body;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        logInfo('HTTP', `[${reqId}] invalid JSON body: ${err.message}`);
        sendJson(res, 400, { error: { message: 'Invalid JSON body', type: 'invalid_request_error' } });
        return;
      }

      const completionId = `chatcmpl-${crypto.randomUUID()}`;
      const created = Math.floor(Date.now() / 1000);
      const reqModel = body.model || 'aws-quick';
      const { agentMode, thinkingEffort } = parseQuickModelAndEffort(reqModel, body, {
        agentMode: flags['agent-mode'] || process.env.QUICK_AGENT_MODE || 'smart',
        thinkingEffort: flags['thinking-effort'] || process.env.QUICK_THINKING_EFFORT || 'off',
      });
      const hasTools = Array.isArray(body.tools) && body.tools.length > 0;
      const isStream = body.stream === true;
      const totalMsgs = Array.isArray(body.messages) ? body.messages.length : 0;
      const msgHashes = (Array.isArray(body.messages) ? body.messages : []).map(hashMessage);
      const { rec: sessionRec, startIndex, isFork } = sessionManager.resolveSession(req, body);
      const promptChunks = formatMessagesForQuick(body.messages, body.tools, body.tool_choice, {
        startIndex,
      });
      const promptText = promptChunks[promptChunks.length - 1] || '';
      const totalPromptBytes = promptChunks.reduce((acc, c) => acc + Buffer.byteLength(c, 'utf8'), 0);
      logInfo(
        'CHAT',
        `[${reqId}] session=${sessionRec.sessionKey} thread=${sessionRec.threadId} fork=${isFork} model=${reqModel} mode=${agentMode} effort=${thinkingEffort} stream=${isStream} tools=${hasTools ? body.tools.length : 0} msgs=${totalMsgs} startIdx=${startIndex} chunks=${promptChunks.length} promptBytes=${totalPromptBytes}`
      );

      const ac = new AbortController();
      req.on('close', () => {
        if (!res.writableEnded) ac.abort();
      });

      if (isStream) {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no',
          'Access-Control-Allow-Origin': '*',
          'X-Quick-Session-Id': sessionRec.workingSessionId,
          'X-Quick-Thread-Id': sessionRec.threadId,
        });
        res.flushHeaders?.();

        const writeChunk = (delta, finishReason = null) => {
          if (res.writableEnded) return;
          const chunk = {
            id: completionId,
            object: 'chat.completion.chunk',
            created,
            model: reqModel,
            choices: [{ index: 0, delta, finish_reason: finishReason }],
          };
          res.write(`data: ${JSON.stringify(chunk)}\n\n`);
        };

        writeChunk({ role: 'assistant' });

        try {
          await sessionManager.enqueue(sessionRec, async (rec) => {
            if (hasTools) {
              let emittedToolCalls = 0;
              const filter = createStreamingToolFilter({
                onText: (t) => writeChunk({ content: t }),
                onToolCall: (tc) => {
                  emittedToolCalls++;
                  writeChunk({ tool_calls: [tc] });
                },
              });

              const result = await callWithAutoRefresh({
                reqId,
                sessionRec: rec,
                workingSessionId: rec.workingSessionId,
                threadId: rec.threadId,
                agentMode,
                thinkingEffort,
                clientTools: body.tools,
                messages: body.messages,
                promptText,
                promptChunks,
                signal: ac.signal,
                onThought: (t) => writeChunk({ reasoning_content: t }),
                onDelta: (d) => filter.push(d),
              });
              filter.flush();

              if (result.toolCalls && result.toolCalls.length > 0) {
                for (let i = 0; i < result.toolCalls.length; i++) {
                  writeChunk({ tool_calls: [{ index: emittedToolCalls + i, ...result.toolCalls[i] }] });
                }
                emittedToolCalls += result.toolCalls.length;
              }
              writeChunk({}, emittedToolCalls > 0 ? 'tool_calls' : 'stop');
              sessionManager.commitHashes(rec, msgHashes);
            } else {
              await callWithAutoRefresh({
                reqId,
                sessionRec: rec,
                workingSessionId: rec.workingSessionId,
                threadId: rec.threadId,
                agentMode,
                thinkingEffort,
                messages: body.messages,
                promptText,
                promptChunks,
                signal: ac.signal,
                onThought: (t) => writeChunk({ reasoning_content: t }),
                onDelta: (d) => writeChunk({ content: d }),
              });
              writeChunk({}, 'stop');
              sessionManager.commitHashes(rec, msgHashes);
            }
          });
          res.write('data: [DONE]\n\n');
          res.end();
        } catch (err) {
          if (!res.writableEnded) {
            res.write(`data: ${JSON.stringify({ error: { message: err.message } })}\n\n`);
            res.write('data: [DONE]\n\n');
            res.end();
          }
        }
        return;
      }

      // 非流式响应
      try {
        const result = await sessionManager.enqueue(sessionRec, (rec) =>
          callWithAutoRefresh({
            reqId,
            sessionRec: rec,
            workingSessionId: rec.workingSessionId,
            threadId: rec.threadId,
            agentMode,
            thinkingEffort,
            clientTools: body.tools,
            messages: body.messages,
            promptText,
            promptChunks,
            signal: ac.signal,
          })
        );
        let toolCalls = result.toolCalls || [];
        let cleanText = result.text || '';
        if (toolCalls.length === 0 && hasTools) {
          const extracted = extractToolCallsFromText(result.text || '');
          toolCalls = extracted.toolCalls;
          cleanText = extracted.cleanText;
        }

        res.setHeader('X-Quick-Session-Id', sessionRec.workingSessionId);
        res.setHeader('X-Quick-Thread-Id', sessionRec.threadId);
        sessionManager.commitHashes(sessionRec, msgHashes);
        sendJson(res, 200, {
          id: completionId,
          object: 'chat.completion',
          created,
          model: result.model || reqModel,
          choices: [
            {
              index: 0,
              message: {
                role: 'assistant',
                content: toolCalls.length > 0 ? (cleanText || null) : result.text,
                ...(toolCalls.length > 0
                  ? {
                      tool_calls: toolCalls.map(({ id, type, function: fn }) => ({
                        id,
                        type,
                        function: fn,
                      })),
                    }
                  : {}),
                ...(result.thought ? { reasoning_content: result.thought } : {}),
              },
              finish_reason: toolCalls.length > 0 ? 'tool_calls' : 'stop',
            },
          ],
          usage: {
            prompt_tokens: result.usage?.input_tokens ?? 0,
            completion_tokens: result.usage?.output_tokens ?? 0,
            total_tokens: result.usage?.total_tokens ?? 0,
          },
        });
      } catch (err) {
        sendJson(res, 500, { error: { message: err.message, type: 'api_error' } });
      }
      return;
    }

    sendJson(res, 404, { error: { message: `Not found: ${req.method} ${urlPath}` } });
  });

  server.requestTimeout = 0;
  server.on('clientError', (err, socket) => {
    logInfo('HTTP', `clientError: ${err.code || err.message}`);
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  server.listen(port, host, () => {
    logInfo('SERVER', `Listening on http://${host}:${port}/v1 (provider=${creds.provider}, debug=${DEBUG_ENABLED})`);
  });
}

// ---------------------------------------------------------------------------
// CLI 入口解析
// ---------------------------------------------------------------------------

function parseCli(argv) {
  const [command, ...rest] = argv;
  const flags = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = 'true';
      }
    }
  }
  return { command, flags };
}

function printHelp() {
  process.stdout.write(`quick-openai - AWS Quick 浏览器扩展凭证获取与 OpenAI Compatible API 代理 (纯 Node.js 标准库)

Usage:
  node aws-quick-openai-api.mjs creds [--region us-east-1] [--alias <dir>] [--cookie <cookie>] [--relogin] [--creds-file <path>]
  node aws-quick-openai-api.mjs serve [--host 127.0.0.1] [--port 8080] [--creds-file <path>] [--sessions-file <path>] [--api-key <key>] [--debug]

Options:
  --creds-file      凭证 JSON 路径（默认 ./credentials.json）
  --sessions-file   会话持久化 JSON 路径（默认 ./sessions.json）

Env vars for "serve":
  OPENAI_API_KEY    (可选) 保护本地 OpenAI API 的 Bearer key

Example:
  node aws-quick-openai-api.mjs creds
  node aws-quick-openai-api.mjs serve --port 8080
`);
}

const { command, flags } = parseCli(process.argv.slice(2));
if (command === 'creds') {
  runCredsCommand(flags).catch((err) => {
    process.stderr.write(`[quick-openai] Error: ${err.message}\n`);
    process.exit(1);
  });
} else if (command === 'serve') {
  runServeCommand(flags).catch((err) => {
    process.stderr.write(`[quick-openai] Error: ${err.message}\n`);
    process.exit(1);
  });
} else {
  printHelp();
  process.exit(command ? 1 : 0);
}
