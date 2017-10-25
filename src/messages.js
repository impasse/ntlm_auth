const struct = require('python-struct');
const crypto = require('crypto');
const ComputeResponse = require('./compute_response');
const {
    NTLM_SIGNATURE,
    MessageTypes,
    NegotiateFlags,
} = require('./constants');
const { RC4 } = require('./util');

function get_version(negotiateFlags) {
    if (negotiateFlags & NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION) {
        const majorVersion = struct.pack('<B', 6);
        const minorVersion = struct.pack('<B', 1);
        const build = struct.pack('<H', 7601);
        const versionReserved = '\0\0\0';
        const nltmRevisionCurrent = struct.pack('<B', 15);
        return Buffer.concat([
            majorVersion,
            minorVersion,
            build,
            versionReserved,
            nltmRevisionCurrent,
        ]);
    } else {
        return Buffer.alloc(8);
    }
}

class NegotiateMessage{
    constructor(negotiate_flags, domain_name, workstation) {
        this.signature = NTLM_SIGNATURE;
        this.messageType = struct.pack('<L', MessageTypes.NTLM_NEGOTIATE);
        if (domain_name) {
            this.domain_name = domain_name;
            negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
        } else {
            this.domain_name = '';
        }
        if (workstation) {
            this.workstation = workstation;
            negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
        } else {
            this.workstation = '';
        }
        negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE;
        negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM;
        this.version = get_version(negotiate_flags);
        this.negotiate_flags = struct.pack('<I', negotiate_flags);
    }

    get_data() {
        let payload_offset = 40;
        const domain_name_len = struct.pack('<H', this.domain_name.length);
        const domain_name_max_len = struct.pack('<H', this.domain_name.length);
        const domain_name_buffer_offset = struct.pack('<I', payload_offset);
        payload_offset += this.domain_name.length;

        const workstation_len = struct.pack('<H', this.workstation.length);
        const workstation_max_len = struct.pack('<H', this.workstation.length);
        const workstation_buffer_offset = struct.pack('<I', payload_offset);
        payload_offset += this.workstation.length;

        const msg = Buffer.concat([
            this.signature,
            this.messageType,
            this.negotiate_flags,
            domain_name_len,
            domain_name_max_len,
            domain_name_buffer_offset,
            workstation_len,
            workstation_max_len,
            workstation_buffer_offset,
            this.version,
        ]);

        return Buffer.concat([
            msg,
            Buffer.from(this.domain_name, 'ascii'),
            Buffer.from(this.workstation, 'ascii'),
        ]).toString('base64');
    }
}

class ChallengeMessage{
    constructor(msg) {
        this.data = msg;
        this.signature = msg.slice(0, 8);
        this.message_type = struct.unpack('<I', msg.slice(8, 12))[0];
        this.negotiate_flags = struct.unpack('<I', msg.slice(20, 24))[0];
        this.server_challenge = msg.slice(24, 32);
        this.reserved = msg.slice(32, 40);

        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION
            && this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            && msg.length > 48) {
            this.version = struct.unpack("<q", msg.slice(48, 56))[0];
        }
        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_REQUEST_TARGET) {
            const target_name_len = struct.unpack('<H', msg.slice(12, 14))[0];
            const target_name_max_len = struct.unpack('<H', msg.slice(14, 16))[0];
            const target_name_buffer_offset = struct.unpack('<I', msg.slice(16, 20))[0];
            this.target_name = msg.slice(target_name_buffer_offset, target_name_buffer_offset + target_name_len);
        }
        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO) {
            const target_info_len = struct.unpack("<H", msg2.slice(40, 42))[0];
            const target_info_max_len = struct.unpack('<H', msg.slice(42, 44))[0];
            const target_info_buffer_offset = struct.unpack('<I', msg.slice(44, 48))[0];
            const target_info_raw = msg.slice(target_info_buffer_offset, target_info_buffer_offset + target_info_len);
            this.target_info = new target_info_buffer_offset(target_info_raw);
        }
    }

    get_data() {
        return this.data;
    }
}

class AuthenticateMessage {
    constructor(user_name, password, domain_name, workstation, challenge_message, ntlm_compatibility, server_certificate_hash) {
        this.signature = NTLM_SIGNATURE;
        this.message_type = struct.pack('<L', MessageTypes.NTLM_AUTHENTICATE);
        this.negotiate_flags = challenge_message.NegotiateFlags;
        this.version = get_version(this.negotiate_flags);
        this.mic = null;
        this.domain_name = domain_name || '';
        this.workstation = workstation || '';
        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE) {
            this.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM;
            this.encoding = 'utf16le';
        } else {
            this.encoding = 'ascii';
        }
        this.user_name = user_name;
        const compute_response = new ComputeResponse(user_name, password, domain_name, challenge_message, ntlm_compatibility);
        this.lm_challenge_response = compute_response.get_lm_challenge_response();
        const [nt_challenge_response, key_exchange_key, target_info] = compute_response.get_nt_challenge_response(self.lm_challenge_response, server_certificate_hash);
        this.nt_challenge_response = nt_challenge_response;
        this.target_info = target_info;

        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH) {
            this.exported_session_key = crypto.pseudoRandomBytes(16);
            const rc4 = RC4(key_exchange_key);
            this.encrypted_random_session_key = rc4.update(this.exported_session_key);
            rc4.final();
        } else {
            this.exported_session_key = key_exchange_key;
            this.encrypted_random_session_key = Buffer.alloc(0);
        }
        this.negotiate_flags = struct.pack('<I', this.negotiate_flags);
    }

    get_data() {
        let mic, expected_body_length = 72;
        if (this.mic) {
            mic = this.mic;
            expected_body_length = 80;
        }
        payload_offset = expected_body_length;

        const domain_name_len = struct.pack('<H', self.domain_name.length);
        const domain_name_max_len = struct.pack('<H', self.domain_name.length);
        const domain_name_buffer_offset = struct.pack('<I', payload_offset);
        payload_offset += self.domain_name.length;

        const user_name_len = struct.pack('<H', self.user_name.length);
        const user_name_max_len = struct.pack('<H', self.user_name.length);
        const user_name_buffer_offset = struct.pack('<I', payload_offset);
        payload_offset += self.user_name.length;

        const workstation_len = struct.pack('<H', self.workstation.length);
        const workstation_max_len = struct.pack('<H', self.workstation.length);
        const workstation_buffer_offset = struct.pack('<I', payload_offset);
        payload_offset += self.workstation.length;

        const lm_challenge_response_len = struct.pack('<H', self.lm_challenge_response.length);
        const lm_challenge_response_max_len = struct.pack('<H', self.lm_challenge_response.length);
        const lm_challenge_response_buffer_offset = struct.pack('<I', payload_offset);
        payload_offset += self.lm_challenge_response.length;

        const nt_challenge_response_len = struct.pack('<H', self.nt_challenge_response.length);
        const nt_challenge_response_max_len = struct.pack('<H', self.nt_challenge_response.length);
        const nt_challenge_response_buffer_offset = struct.pack('<I', payload_offset);
        payload_offset += self.nt_challenge_response.length;

        encrypted_random_session_key_len = struct.pack('<H', self.encrypted_random_session_key.length);
        encrypted_random_session_key_max_len = struct.pack('<H', self.encrypted_random_session_key.length);
        encrypted_random_session_key_buffer_offset = struct.pack('<I', payload_offset);
        payload_offset += self.encrypted_random_session_key.length;

        const payload = Buffer.concat([
            this.domain_name,
            this.user_name,
            this.workstation,
            this.lm_challenge_response,
            this.nt_challenge_response,
            this.encrypted_random_session_key,
        ]);

        const msg3 = Buffer.concat([
            this.signature,
            this.message_type,
            lm_challenge_response_len,
            lm_challenge_response_max_len,
            lm_challenge_response_buffer_offset,
            nt_challenge_response_len,
            nt_challenge_response_max_len,
            nt_challenge_response_buffer_offset,
            domain_name_len,
            domain_name_max_len,
            domain_name_buffer_offset,
            user_name_len,
            user_name_max_len,
            user_name_buffer_offset,
            workstation_len,
            workstation_max_len,
            workstation_buffer_offset,
            encrypted_random_session_key_len,
            encrypted_random_session_key_max_len,
            encrypted_random_session_key_buffer_offset,
            this.negotiate_flags,
            this.version,
            mic,
        ]);
        return Buffer.concat([msg3, payload]);
    }
}


module.exports = {
    NegotiateMessage,
    ChallengeMessage,
    AuthenticateMessage,
};
