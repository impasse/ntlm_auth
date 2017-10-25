const struct = require('python-struct');
const {
    NegotiateFlags,
} = require('./constants');
const {
    NegotiateMessage,
    ChallengeMessage,
    AuthenticateMessage,
} = require('./messages');
const SessionSecurity = require('./session_security');


class Ntlm {
    constructor(ntlm_compatibility = 3) {
        this.ntlm_compatibility = ntlm_compatibility;
        this.negotiate_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
            NegotiateFlags.NTLMSSP_NEGOTIATE_128 |
            NegotiateFlags.NTLMSSP_NEGOTIATE_56 |
            NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE |
            NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION |
            NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH |
            NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
            NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN |
            NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL;
        this._set_ntlm_compatibility_flags(this.ntlm_compatibility);

        this.negotiate_message = null;
        this.challenge_message = null;
        this.authenticate_message = null;
        this.session_security = null;
    }

    create_negotiate_message(domain_name, workstation) {
        this.negotiate_message = new NegotiateMessage(this.negotiate_flags, domain_name, workstation);
        return this.negotiate_message.toString('base64');
    }

    parse_challenge_message(msg2) {
        msg2 = Buffer.from(msg2, 'base64');
        self.challenge_message = ChallengeMessage(msg2);
    }

    create_authenticate_message(user_name, password, domain_name, workstation, server_certificate_hash) {
        this.authenticate_message = AuthenticateMessage(
            user_name,
            password,
            domain_name,
            workstation,
            this.challenge_message,
            this.ntlm_compatibility,
            server_certificate_hash
        );
        this.authenticate_message.add_mic(this.negotiate_message, this.challenge_message);

        if (this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL || this.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN) {
            this.session_security = new SessionSecurity(
                struct.unpack('<I', this.authenticate_message.negotiate_flags)[0],
                this.authenticate_message.exported_session_key
            );
        }
        return this.authenticate_message.toString('base64');
    }

    _set_ntlm_compatibility_flags(ntlm_compatibility) {
        if (ntlm_compatibility >= 0 && ntlm_compatibility <= 5) {
            if (ntlm_compatibility === 0) {
                this.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY;
            } else if (ntlm_compatibility === 1) {
                this.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
            } else {
                this.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
            }
        } else {
            throw new Error('Unknown ntlm_compatibility level - expecting value between 0 and 5');
        }
    }
}