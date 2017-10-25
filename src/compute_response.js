const crypto = require('crypto');
const struct = require('python-struct');
const comkeys = require('./compute_keys');
const comphash = require('./compute_hash');
const { DES } = require('./util');
const {
    NegotiateFlags,
    AvFlags,
} = require('./constants');


function get_windows_timestamp() {
    return struct.pack('<q', (116444736000000000 + Date.now() * 10000000));
}

class ComputeResponse {
    constructor(user_name, password, domain_name, challenge_message, ntlm_compatibility) {
        this._user_name = user_name;
        this._password = password;
        this._domain_name = domain_name;
        this._challenge_message = challenge_message;
        this._negotiate_flags = challenge_message.negotiate_flags;
        this._server_challenge = challenge_message.server_challenge;
        this._server_target_info = challenge_message.target_info;
        this._ntlm_compatibility = ntlm_compatibility;
        this._client_challenge = crypto.pseudoRandomBytes(8);
    }

    get_lm_challenge_response() {
        let response, ignore_key, timestamp;
        if (this._negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        && this._ntlm_compatibility < 3) {
            response = ComputeResponse._get_LMv1_with_session_security_response(this._client_challenge);
        } else if (this._ntlm_compatibility >= 0 && this._ntlm_compatibility <=1) {
            response = ComputeResponse._get_LMv1_response(this._password, this._server_challenge);
        } else if (this._ntlm_compatibility === 2) {
            [response, ignore_key] = ComputeResponse._get_NTLMv1_response(this._password, this._server_challenge);
        } else {
            response = ComputeResponse._get_LMv2_response(
                this._user_name,
                this._password,
                this._domain_name,
                this._server_challenge,
                this._client_challenge
            );
            if (this._server_target_info) {
                timestamp = this._server_target_info[TargetInfo.MSV_AV_TIMESTAMP];
                if (timestamp) {
                    response = Buffer.alloc(24);
                }
            }
        }
        return response;
    }

    get_nt_challenge_response(lm_challenge_response, server_certificate_hash) {
        let response, session_base_key, key_exchange_key, target_info, channel_bindings_hash;
        if (this._negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        && this._ntlm_compatibility < 3) {
            [response, session_base_key] = ComputeResponse._get_NTLM2_response(
                this._password,
                this._server_challenge,
                this._client_challenge
            );
            key_exchange_key = compkeys._get_exchange_key_ntlm_v1(
                this._negotiate_flags,
                session_base_key,
                this._server_challenge,
                lm_challenge_response,
                comphash._lmowfv1(this._password)
            );
        } else if (this._ntlm_compatibility >= 0 && this._ntlm_compatibility < 3) {
            [response, session_base_key] = ComputeResponse._get_NTLMv1_response(
                this._password,
                this._server_challenge
            );
            key_exchange_key = comkeys._get_exchange_key_ntlm_v1(
                this._negotiate_flags,
                session_base_key,
                this._server_challenge,
                lm_challenge_response,
                comphash._lmowfv1(this._password)
            );
        } else {
            target_info = this._server_target_info || new TargetInfo();
            if (!target_info[TargetInfo.MSV_AV_TIMESTAMP]) {
                timestamp = get_windows_timestamp();
            } else {
                timestamp = target_info[TargetInfo.MSV_AV_TIMESTAMP][1];
                target_info[TargetInfo.MSV_AV_FLAGS] = struct.pack('<L', AvFlags.MIC_PROVIDED);
            }
            if (server_certificate_hash) {
                channel_bindings_hash = ComputeResponse._get_channel_bindings_value(server_certificate_hash);
                target_info[TargetInfo.MSV_AV_CHANNEL_BINDINGS] = channel_bindings_hash;
            }
            [response, session_base_key] = ComputeResponse._get_NTLMv2_response(
                this._user_name,
                this._password,
                this._domain_name,
                this._server_challenge,
                this._client_challenge,
                timestamp,
                target_info
            );
            key_exchange_key = compkeys._get_exchange_key_ntlm_v2(session_base_key);
        }
        return [response, key_exchange_key, target_info];
    }

    static _get_LMv1_response(password, server_challenge) {
        const lm_hash = comphash._lmowfv1(password);
        return ComputeResponse._calc_resp(lm_hash, server_challenge);
    }

    static _get_LMv1_with_session_security_response(client_challenge) {
        return Buffer.concat([
            client_challenge,
            Buffer.alloc(16),
        ]);
    }

    static _get_LMv2_response(user_name, password, domain_name, server_challenge, client_challenge) {
        const nt_hash = comphash._ntowfv2(user_name, password, domain_name)
        const lm_hash = crypto.createHmac('md5', nt_hash)
        .update(Buffer.concat([
            server_challenge,
            client_challenge,
        ]))
        .digest();
        return Buffer.concat([
            lm_hash,
            client_challenge,
        ]);
    }

    static _get_NTLMv1_response(password, server_challenge) {
        const ntlm_hash = comphash._ntowfv1(password);
        const response = ComputeResponse._calc_resp(ntlm_hash, server_challenge);
        const session_base_key = crypto.createHash('md4').update(ntlm_hash).digest();
        return [response, session_base_key];
    }

    static _get_NTLM2_response(password, server_challenge, client_challenge) {
        const ntlm_hash = comphash._ntowfv1(password);
        const nt_session_hash = crypto.createHash('md5')
        .update(Buffer.concat([
            server_challenge,
            client_challenge,
        ]))
        .digest()
        .slice(0, 8);
        const response = ComputeResponse._calc_resp(ntlm_hash, nt_session_hash.slice(0,8));
        const session_base_key = crypto.createHash('md4').update(ntlm_hash).digest();
        return [response, session_base_key];
    }

    static _get_NTLMv2_response(user_name, password, domain_name, server_challenge, client_challenge, timestamp, target_info) {
        const ntlm_hash = comphash._ntowfv2(user_name, password, domain_name);
        const temp = ComputeResponse._get_NTLMv2_temp(timestamp, client_challenge, target_info);
        const nt_proof_str = crypto.createHmac('md5', nt_hash)
        .update(Buffer.concat([
            server_challenge,
            temp,
        ]))
        .digest();
        const response = Buffer.concat([nt_proof_str, temp]);
        const session_base_key = crypto.createHmac('md5', nt_hash)
        .update(nt_proof_str)
        .digest();
        return [response, session_base_key];
    }

    static _get_NTLMv2_temp(timestamp, client_challenge, target_info) {
        const resp_type = Buffer.alloc(1, 1);
        const hi_resp_type = Buffer.alloc(1, 1);
        const reserved1 = Buffer.alloc(2);
        const reserved2 = Buffer.alloc(4);
        const reserved3 = Buffer.alloc(4);
        const reserved4 = Buffer.alloc(4);
        return Buffer.concat([
            resp_type,
            hi_resp_type,
            reserved1,
            reserved2,
            timestamp,
            client_challenge,
            reserved3,
            target_info.get_data(),
            reserved4,
        ]);
    }

    static _calc_resp(password_hash, server_challenge) {
        password_hash = Buffer.concat([
            password_hash,
            Buffer.alloc(21 - password_hash.length),
        ]);
        return Buffer.concat([
            DES(password_hash.slice(0, 7)).update(server_challenge.slice(0, 8).digest()),
            DES(password_hash.slice(7, 14)).update(server_challenge.slice(0, 8).digest()),
            DES(password_hash.slice(14, 21)).update(server_challenge.slice(0, 8).digest())
        ]);
    }

    static _get_channel_bindings_value(server_certificate_hash) {
        const certificate_digest = Buffer.from(server_certificate_hash, 'hex');

        const gss_channel_bindings = new GssChannelBindingsStruct();
        gss_channel_bindings[gss_channel_bindings.APPLICATION_DATA] = Buffer.concat([
            Buffer.from('tls-server-end-point:'),
            certificate_digest
        ]);
        const channel_bindings_struct_data = gss_channel_bindings.get_data()
        return crypto.createHash('md5')
        .update(channel_bindings_struct_data)
        .digest();
    }
}

module.exports = ComputeResponse;
