const crypto = require('crypto');
const { DES } = require('./util');
const {
    NegotiateFlags,
} = require('./constants');

function unhexlify(str) {
    return Buffer.from(str, 'hex');
}

function _get_exchange_key_ntlm_v1(negotiate_flags, session_base_key, server_challenge, lm_challenge_response, lm_hash) {
    let key_exchange_key, des_handler, first_des, second_des;
    if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        key_exchange_key = crypto.createHmac(
            'md5',
            session_base_key,
        )
        .update(
            Buffer.concat([server_challenge, lm_challenge_response.slice(0, 8)])
        )
        .digest();
    } else if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY) {
        des_handler = DES(lm_hash.slice(0, 7));
        first_des = DES.update(lm_challenge_response.slice(0, 8)).digest();
        des_handler = DES(
            Buffer.concat([
                lm_hash.slice(7, 8) + unhexlify('bdbdbdbdbdbdbd')
            ])
        );
        second_des = des_handler.update(lm_challenge_response.slice(0, 8)).digest();

        key_exchange_key = Buffer.concat([first_des, second_des]);
    } else if (negotiate_flags & NegotiateFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY) {
        key_exchange_key = Buffer.concat([
            lm_hash.slice(0, 8),
            Buffer.from('\0\0\0\0\0\0\0\0'),
        ]);
    } else {
        key_exchange_key = session_base_key;
    }
    return key_exchange_key;
}


function _get_exchange_key_ntlm_v2(session_base_key) {
    return session_base_key;
}

function get_sign_key(exported_session_key, magic_constant) {
    return crypto.createHash('md5').update(
        Buffer.concat([
            exported_session_key,
            magic_constant,
        ])
    )
    .digest();
}

function get_seal_key(negotiate_flags, exported_session_key, magic_constant) {
    let seal_key;
    if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        seal_key = _get_seal_key_ntlm2(negotiate_flags, exported_session_key, magic_constant);
    } else if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY) {
        seal_key = _get_seal_key_ntlm1(negotiate_flags, exported_session_key);
    } else {
        seal_key = exported_session_key;
    }
    return seal_key;
}

function _get_seal_key_ntlm1(negotiate_flags, exported_session_key) {
    let seal_key;
    if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_56) {
        seal_key = Buffer.concat([
            exported_session_key.slice(0, 7),
            unhexlify('a0')
        ]);
    } else {
        seal_key = Buffer.concat([
            exported_session_key.slice(0, 5),
            unhexlify('e538b0'),
        ]);
    }
    return seal_key;
}

function _get_seal_key_ntlm2(negotiate_flags, exported_session_key, magic_constant) {
    let seal_key;
    if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_128) {
        seal_key = exported_session_key;
    } else if (negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_56) {
        seal_key = exported_session_key.slice(0, 7);
    } else {
        seal_key = exported_session_key.slice(0, 5);
    }
    return crypto.createHash('md5')
    .update(Buffer.concat([
        seal_key,
        magic_constant,
    ]))
    .digest();
}

module.exports = {
    unhexlify,
    _get_exchange_key_ntlm_v1,
    _get_exchange_key_ntlm_v2,
    get_sign_key,
    get_seal_key,
    _get_seal_key_ntlm1,
    _get_seal_key_ntlm2,
}
