import { Observable, Subject } from 'rxjs';
import MessageSocket from 'message-socket';
import BufferReader from 'buffer-reader';

import {
    indexOf,
    mark,
    seekToMark,
    nextLine,
    remaining
} from './lib/bufferreader';

import tlv from './lib/tlv';

import { splitGen as split } from './lib/string';

import debug from 'debug';

const logger = debug('hap-client:http');

function readChunk() {
    // read one line
    let size = nextLine.call(this), chunk = '';
    if (size) {
        size = parseInt(size, 16);
        logger(`reading ${size} bytes for chunk`);
        if (size > 0) {
            if (size < (this.offset + this.buf.length)) {
                chunk = this.nextBuffer(size);
                this.move(2);
            }
            else {
                chunk = null;
            }
        }

        return [size, chunk];
    }

    return null;
}

const Decoders = {
    'application/pairing+tlv8': (buffer) =>
        tlv.decode(buffer.restAll())
    ,
    'application/hap+json': (buffer) => {
        const body = buffer.restAll().toString('utf8');
        return JSON.parse(body)
    }
};

const Encoders = {
    /*
    'application/pairing+tlv8': (buffer) =>
        tlv.decode(buffer.restAll())
    ,
    */
    'application/hap+json': (object) => {
        return Buffer.from(JSON.stringify(object), 'utf8');
    }
};

function runMiddleware(funcName, obj) {
    return this
        ._middleware
        .reduce(
            (acc, next) => {
                if (next && next[funcName]) {
                    acc = next[funcName](acc);
                    if (acc === null) {
                        throw new Error("Middleware failure");
                    }
                }
                return acc;
            },
            obj
        );
}

class EventedHttpClient {
    constructor(host, port = 80) {
        Object.defineProperty(
            this, '_host', {
            value: host
        }
        );

        Object.defineProperty(
            this, '_port', {
            value: port
        }
        );

        Object.defineProperty(
            this, '_socket', {
            value: new MessageSocket(host, port, _bufferSplitter.call(this), null)
        }
        );

        Object.defineProperty(
            this, '_middleware', {
            value: []
        }
        );

        Object.defineProperty(
            this, '_isClosing', {
            value: new Subject()
        }
        );
    }

    get messages() {
        return Observable
            .from(
                this._socket
            )
            .takeUntil(
                this._isClosing
            )
    }

    addMiddleware(obj) {
        this._middleware.push(obj);
    }

    request(method, url, headers, data) {
        return Observable
            .defer(
                () => {
                    logger(`requesting: ${method} ${url}`);

                    let request = {
                        method,
                        url,
                        headers,
                        body: data ? data : Buffer.alloc(0)
                    };

                    request =
                        runMiddleware.call(this,
                            'handleRequest',
                            request
                        );

                    let outgoing =
                        Buffer
                            .concat([
                                Buffer.from(
                                    `${request.method.toUpperCase()} ${request.url} HTTP/1.1\r\n` +
                                    `Host: ${this._host}:${this._port}\r\n` +

                                    Object
                                        .keys(request.headers)
                                        .reduce(
                                            (acc, h) =>
                                                acc + `${h}: ${request.headers[h]}\r\n`
                                            , ''
                                        ) +

                                    '\r\n'
                                ),

                                request.body
                            ]);

                    logger("raw request: %s", outgoing.toString('hex'));

                    outgoing =
                        runMiddleware.call(this,
                            'handleRawRequest',
                            outgoing
                        );

                    logger("raw request (post middleware): %s", outgoing.toString('hex'));

                    this._socket.send(outgoing);

                    logger("Request sent");

                    return this
                        .messages
                        .filter(x => x.type !== 'EVENT/1.0')
                        .take(1)
                }
            )
    }

    get(url, headers = {}) {
        logger("GETing %s", url);
        return this
            .request('GET', url, headers);
    }

    post(url, buffer, contentType = 'application/json', headers = {}) {
        logger("POSTing to %s: %o", url, buffer);
        return this
            .request('POST', url, {
                ['Content-Type']: contentType,
                ['Content-Length']: buffer.length,
                ...headers
            }, buffer);
    }

    put(url, data, contentType = 'application/json', headers = {}) {
        logger("PUTing %s: %o", url, data);
        let encoder;
        if (encoder = Encoders[contentType]) {
            data = encoder(data);
        }

        return this
            .request('PUT', url, {
                ['Content-Type']: contentType,
                ['Content-Length']: data.length,
                ...headers
            }, data);
    }

    disconnect() {
        this._socket.close();
        this._isClosing.next();
    }

    _bufferSplitter(buf) {
        const processed =
            runMiddleware.call(this,
                'handleRawResponse',
                buf
            );

        if (processed.length == 0) {
            // need more data.
            return [[], buf];
        }

        let parsed =
            this._parseMessage(new BufferReader(processed));

        return
        runMiddleware.call(this,
            'handleResponse',
            parsed
        );
    }

    _parseMessage(buffer) {
        let messages = [], match;

        // ignore everything until a status line
        let statusRe = /(HTTP|EVENT)\/(\d+\.\d+)\s+(\d{3})\s+(.*?)$/;

        while (indexOf.call(buffer, "\r\n") >= 0) {
            let line = nextLine.call(buffer);

            if (match = statusRe.exec(line)) {
                let [, messageType, version, status, statusText] = match;

                logger(`status: ${messageType}, ${version}, ${status}, ${statusText}`);

                let idx = -1, headers = {};
                while ((idx = indexOf.call(buffer, "\r\n")) > 0) {
                    let header = nextLine.call(buffer);
                    let [name, value] = split.call(header, /:\s*/, 2);

                    headers[name.toLowerCase()] = value;
                }

                // lose the blank line
                buffer.move(2);

                let body = new BufferReader(new Buffer([]));

                if (status != 204) { // "No Content"
                    // is there a content length header?
                    if (headers['content-length']) {
                        let len = parseInt(headers['content-length']);
                        logger(`Reading ${len} bytes for body...`);
                        logger(`There are ${remaining.call(buffer)} bytes left in the buffer`);
                        if (remaining.call(buffer) >= len) {
                            body.append(buffer.nextBuffer(len));
                        } else {
                            // the whole message is not in the buffer
                            // wait till next time
                            logger('partial message; returning');
                            return [[], buffer.buf];
                        }
                    } else if (headers['transfer-encoding'].toLowerCase() === 'chunked') {
                        // TODO: read chunked encoding
                        logger(`Reading chunked bytes for body`);

                        let chunkInfo;
                        while (chunkInfo = readChunk.call(buffer)) {
                            let [declaredSize, chunk] = chunkInfo;
                            if (declaredSize) {
                                if (chunk) {
                                    body.append(chunk);
                                    logger('read chunk sized ' + declaredSize);
                                }
                                else {
                                    // the whole message is not in the buffer
                                    // wait till next time
                                    logger('partial message; returning');
                                    return [[], buffer.buf];
                                }
                            }
                        }

                        // read trailers
                        while ((idx = indexOf.call(buffer, "\r\n")) > 0) {
                            let header = nextLine.call(buffer);
                            let [name, value] = split.call(header, /:\s*/, 2);

                            headers[name.toLowerCase()] = value;
                        }

                        // TODO: I feel like I should need this
                        // buffer.move(2);
                    }
                }

                logger('finished reading');

                let contentType, decoder;
                if ((contentType = headers['content-type'])
                    && (decoder = Decoders[contentType])) {
                    logger('parsing body');
                    body = decoder(body);
                }

                if (body instanceof BufferReader && body.buf.length === 0) {
                    body = null;
                }


                messages.push({ type: `${messageType}/${version}`, status, statusText, headers, body })
                mark.call(buffer);
            }
        }

        seekToMark.call(buffer);
        logger(`returning from ${buffer.offset} to ${buffer.buf.length}`);

        return [messages, buffer.restAll()];
    }
}

export {
    EventedHttpClient as default
}
