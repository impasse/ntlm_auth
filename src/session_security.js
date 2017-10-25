const struct = require('python-struct');
const crypto = require('crypto');
const compkeys = require('./compute_keys');
const {
    SignSealConstants,
    NegotiateFlags,
} = require('./constants');
const { RC4, crc32 } = require('./util');


function calc_signature(message, negotiate_flags, signing_key, seq_num, handle) {
    seq_num = struct.pack('<I', seq_num);
    let checksum, signature;
    if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        let checksum_hmac = crypto.createHmac('md5', signing_key)
        .update(Buffer.concat([
            seq_num,
            message,
        ]));
        if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH) {
            checksum = handle.update(checksum_hmac.digest().slice(0, 8));
        } else {
            checksum = checksum_hmac.digest().slice(0, 8);
        }
        signature = _NtlmMessageSignature2(checksum, seq_num);
    } else {
        const message_crc = crc32(message) % (1 << 32);
        checksum = struct.pack('<I', message_crc);
        const random_pad = handle.update(struct.pack('<I', 0));
        checksum = handle.update(checksum);
        seq_num = handle.update(seq_num);
        random_pad = struct.pack('<I', 0);
        
        signature = _NtlmMessageSignature1(random_pad, checksum, seq_num);
    }
    return signature;
}

class _NtlmMessageSignature1 {
    constructor(random_pad, checksum, seq_num) {
        this.version = struct.pack("<I", 1);
        this.random_pad = random_pad;
        this.checksum = checksum;
        this.seq_num = seq_num;
    }

    get_data() {
        return Buffer.concat([
            this.version,
            this.random_pad,
            this.checksum,
            this.seq_num,
        ]);
    }
}

class _NtlmMessageSignature2 {
    constructor(checksum, seq_num) {
        this.version = struct.pack("<I", 1);
        this.checksum = checksum;
        this.seq_num = seq_num;
    }

    get_data() {
        return Buffer.concat([
            this.version,
            this.checksum,
            this.seq_num,
        ]);
    }
}

class SessionSecurity {
    constructor(negotiate_flags, exported_session_key, source="client") {
        this.negotiate_flags = negotiate_flags;
        this.outgoing_seq_num = 0;
        this.incoming_seq_num = 0;

        const client_sealing_key = compkeys.get_seal_key(this.negotiate_flags, exported_session_key, SignSealConstants.CLIENT_SEALING);
        const server_sealing_key = compkeys.get_seal_key(this.negotiate_flags, exported_session_key, SignSealConstants.SERVER_SEALING);

        if (source === "client") {
            this.outgoing_signing_key = compkeys.get_sign_key(exported_session_key, SignSealConstants.CLIENT_SIGNING);
            this.incoming_signing_key = compkeys.get_sign_key(exported_session_key, SignSealConstants.SERVER_SIGNING);
            this.outgoing_handle = RC4(client_sealing_key);
            this.incoming_handle = RC4(server_sealing_key);
        } else if (source === 'server') {
            this.outgoing_signing_key = compkeys.get_sign_key(exported_session_key, SignSealConstants.SERVER_SIGNING);
            this.incoming_signing_key = compkeys.get_sign_key(exported_session_key, SignSealConstants.CLIENT_SIGNING);
            this.outgoing_handle = RC4(server_sealing_key);
            this.incoming_handle = RC4(client_sealing_key);
        } else {
            throw new Error(`Invalid source parameter ${source}, must be client or server`);
        }
    }

    wrap(message) {
        let signature;
        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL) {
            const encrypted_message = this._seal_message(message);
            signature = this._get_signature(message);
            message = encrypted_message;
        } else if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN) {
            signature = this._get_signature(message);
        } else {
            signature = null;
        }
        return [message, signature];
    }

    unwrap(message, signature) {
        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL) {
            message = this._unseal_message(message);
            this._verify_signature(message, signature);
        } else if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN) {
            this._verify_signature(message, signature);
        }
        return message;
    }

    _seal_message(message) {
        return this.outgoing_handle(message);
    }

    _unseal_message(message) {
        return this.incoming_handle(message);
    }

    _get_signature(message) {
        const signature = calc_signature(message, this.negotiate_flags, this.outgoing_signing_key, this.outgoing_seq_num, this.outgoing_handle);
        this.outgoing_seq_num += 1;
        return signature.get_data();
    }

    _verify_signature(message, signature) {
        let actual_checksum, actual_seq_num;
        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
            actual_checksum = signature.slice(4, 12)
            actual_seq_num = struct.unpack("<I", signature.slice(12, 16))[0];
        } else {
            actual_checksum = signature.slice(8, 12);
            actual_seq_num = struct.unpack('<I', signature.slice(12, 16))[0];
        }
        const expected_signature = calc_signature(message, this.negotiate_flags, this.incoming_signing_key, this.incoming_seq_num, this.incoming_handle);
        const expected_checksum = expected_signature.checksum;
        const expected_seq_num = struct.unpack("<I", expected_signature.seq_num)[0];

        if (actual_checksum != expected_checksum) {
            throw new Error("The signature checksum does not match, message has been altered");
        }

        if (actual_seq_num != expected_seq_num) {
            throw new  Error("The signature sequence number does not match up, message not received in the correct sequence");
        }
        this.incoming_seq_num += 1;
    }
}
