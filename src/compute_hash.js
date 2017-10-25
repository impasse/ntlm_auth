const crypto = require('crypto');
const { DES } = require('./util');

function _lmowfv1(password) {
    if (/^[a-fA-F\d]{32}:[a-fA-F\d]{32}$/.test(password)) {
        const lm_hash = Buffer.from(password.split(':')[0], 'hex');
        return lm_hash;
    }
    password = password.toUpperCase();
    const lm_pw = password.slice(0, 14);
    const magic_str = 'KGS!@#$%';

    let res = Buffer.from('');
    const dobj = DES(lm_pw.slice(0, 7));
    return Buffer.concat([
        DES(lm_pw.slice(0, 7)).update(magic_str).digest(),
        DES(lm_pw.slice(7, 14)).update(magic_str).digest(),
    ]);
}

function _ntowfv1(password) {
    if (/^[a-fA-F\d]{32}:[a-fA-F\d]{32}$/.test(password)) {
        const nt_hash = Buffer.from(password.split(':')[0], 'hex');
        return nt_hash;
    }
    return crypto.createHash('md5').update(Buffer.from(password, 'utf16le')).digest();
}

function _ntowfv2(user_name, password, domain_name) {
    let digest = _ntowfv1(password);
    digest = crypto.createHmac('md5', digest)
    .update(Buffer.from(user_name.toUpperCase() + domain_name, 'utf16le'))
    .digest();
    return digest;
}

module.exports = {
    _lmowfv1,
    _ntowfv1,
    _ntowfv2,
};
